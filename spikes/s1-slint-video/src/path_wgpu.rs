//! Path (a): wgpu texture imported into Slint as `slint::Image` (Slint's unstable wgpu integration).
//!
//! A render pass converts YUV planes into an Rgba8Unorm render-target texture which is wrapped with
//! `slint::Image::try_from(wgpu::Texture)`. Planes come from CPU memory (software run) or, on a
//! GPU machine, from a VAAPI surface imported as a Vulkan image through DMA-BUF (see `vk_import`).

use crate::decode::{DecodedFrame, Payload};
use anyhow::{Result, anyhow, bail};
use ffmpeg_next::ffi;
use slint::wgpu_30::wgpu;

const WGSL: &str = "
struct U { mode: u32, w: f32, h: f32, pad: f32 };
@group(0) @binding(0) var t0: texture_2d<f32>;
@group(0) @binding(1) var t1: texture_2d<f32>;
@group(0) @binding(2) var t2: texture_2d<f32>;
@group(0) @binding(3) var smp: sampler;
@group(0) @binding(4) var<uniform> u: U;

@vertex fn vs(@builtin(vertex_index) i: u32) -> @builtin(position) vec4<f32> {
    let p = vec2<f32>(f32((i << 1u) & 2u), f32(i & 2u));
    return vec4<f32>(p * 2.0 - 1.0, 0.0, 1.0);
}

@fragment fn fs(@builtin(position) pos: vec4<f32>) -> @location(0) vec4<f32> {
    let uv = pos.xy / vec2<f32>(u.w, u.h);
    var y = textureSampleLevel(t0, smp, uv, 0.0).r;
    var c: vec2<f32>;
    if (u.mode == 0u) {
        c = vec2<f32>(textureSampleLevel(t1, smp, uv, 0.0).r, textureSampleLevel(t2, smp, uv, 0.0).r);
    } else {
        c = textureSampleLevel(t1, smp, uv, 0.0).rg;
    }
    y = (y - 16.0 / 255.0) * (255.0 / 219.0);
    c = (c - 128.0 / 255.0) * (255.0 / 224.0);
    return vec4<f32>(y + 1.5748 * c.y, y - 0.1873 * c.x - 0.4681 * c.y, y + 1.8556 * c.x, 1.0);
}";

const RING: usize = 3;

pub struct WgpuPresenter {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::RenderPipeline,
    bgl: wgpu::BindGroupLayout,
    sampler: wgpu::Sampler,
    uniform: wgpu::Buffer,
    targets: Vec<wgpu::Texture>,
    target_size: (u32, u32),
    next: usize,
    // CPU plane textures (software path).
    planes: Vec<wgpu::Texture>,
    plane_key: (u32, u32, bool),
    dummy: wgpu::Texture,
    hold: std::collections::VecDeque<std::sync::Arc<crate::decode::DrmFrame>>,
    pub vk: Option<crate::vk_import::VkImporter>,
    pub sync: bool,
    pub info: String,
}

fn tex(device: &wgpu::Device, w: u32, h: u32, fmt: wgpu::TextureFormat, usage: wgpu::TextureUsages) -> wgpu::Texture {
    device.create_texture(&wgpu::TextureDescriptor {
        label: Some("s1"),
        size: wgpu::Extent3d { width: w, height: h, depth_or_array_layers: 1 },
        mip_level_count: 1,
        sample_count: 1,
        dimension: wgpu::TextureDimension::D2,
        format: fmt,
        usage,
        view_formats: &[],
    })
}

impl WgpuPresenter {
    pub fn new(device: wgpu::Device, queue: wgpu::Queue, adapter_info: String, sync: bool, want_dmabuf: bool) -> Result<Self> {
        let module = device.create_shader_module(wgpu::ShaderModuleDescriptor { label: Some("yuv"), source: wgpu::ShaderSource::Wgsl(WGSL.into()) });
        let tb = |binding| wgpu::BindGroupLayoutEntry {
            binding,
            visibility: wgpu::ShaderStages::FRAGMENT,
            ty: wgpu::BindingType::Texture { sample_type: wgpu::TextureSampleType::Float { filterable: true }, view_dimension: wgpu::TextureViewDimension::D2, multisampled: false },
            count: None,
        };
        let bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("yuv-bgl"),
            entries: &[
                tb(0),
                tb(1),
                tb(2),
                wgpu::BindGroupLayoutEntry { binding: 3, visibility: wgpu::ShaderStages::FRAGMENT, ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering), count: None },
                wgpu::BindGroupLayoutEntry {
                    binding: 4,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Buffer { ty: wgpu::BufferBindingType::Uniform, has_dynamic_offset: false, min_binding_size: None },
                    count: None,
                },
            ],
        });
        let layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor { label: None, bind_group_layouts: &[Some(&bgl)], immediate_size: 0 });
        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("yuv"),
            layout: Some(&layout),
            vertex: wgpu::VertexState { module: &module, entry_point: Some("vs"), compilation_options: Default::default(), buffers: &[] },
            fragment: Some(wgpu::FragmentState {
                module: &module,
                entry_point: Some("fs"),
                compilation_options: Default::default(),
                targets: &[Some(wgpu::ColorTargetState { format: wgpu::TextureFormat::Rgba8Unorm, blend: None, write_mask: wgpu::ColorWrites::ALL })],
            }),
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview_mask: None,
            cache: None,
        });
        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            address_mode_u: wgpu::AddressMode::ClampToEdge,
            address_mode_v: wgpu::AddressMode::ClampToEdge,
            ..Default::default()
        });
        let uniform = device.create_buffer(&wgpu::BufferDescriptor { label: Some("u"), size: 16, usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST, mapped_at_creation: false });
        let dummy = tex(&device, 1, 1, wgpu::TextureFormat::R8Unorm, wgpu::TextureUsages::TEXTURE_BINDING);
        let (vk, vk_note) = if want_dmabuf {
            match crate::vk_import::VkImporter::new(&device) {
                Ok(v) => (Some(v), "Vulkan DMA-BUF import available".to_string()),
                Err(e) => (None, format!("Vulkan DMA-BUF import unavailable: {e:#}")),
            }
        } else {
            (None, "DMA-BUF import not requested".to_string())
        };
        Ok(Self {
            device,
            queue,
            pipeline,
            bgl,
            sampler,
            uniform,
            targets: Vec::new(),
            target_size: (0, 0),
            next: 0,
            planes: Vec::new(),
            plane_key: (0, 0, false),
            dummy,
            hold: Default::default(),
            vk,
            sync,
            info: format!("wgpu {adapter_info}; {vk_note}"),
        })
    }

    fn ensure_targets(&mut self, w: u32, h: u32) {
        if self.target_size == (w, h) {
            return;
        }
        self.targets = (0..RING)
            .map(|_| tex(&self.device, w, h, wgpu::TextureFormat::Rgba8Unorm, wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::TEXTURE_BINDING))
            .collect();
        self.target_size = (w, h);
    }

    fn upload_cpu(&mut self, f: &crate::decode::AvFrame) -> Result<(Vec<wgpu::TextureView>, u32)> {
        let (w, h) = (f.width() as u32, f.height() as u32);
        let nv12 = f.format() == ffi::AVPixelFormat::AV_PIX_FMT_NV12 as i32;
        let i420 = f.format() == ffi::AVPixelFormat::AV_PIX_FMT_YUV420P as i32;
        if !nv12 && !i420 {
            bail!("unsupported software pixel format {}", f.format());
        }
        if self.plane_key != (w, h, nv12) || self.planes.is_empty() {
            let u = wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST;
            self.planes = if nv12 {
                vec![tex(&self.device, w, h, wgpu::TextureFormat::R8Unorm, u), tex(&self.device, w / 2, h / 2, wgpu::TextureFormat::Rg8Unorm, u)]
            } else {
                vec![
                    tex(&self.device, w, h, wgpu::TextureFormat::R8Unorm, u),
                    tex(&self.device, w / 2, h / 2, wgpu::TextureFormat::R8Unorm, u),
                    tex(&self.device, w / 2, h / 2, wgpu::TextureFormat::R8Unorm, u),
                ]
            };
            self.plane_key = (w, h, nv12);
        }
        for (i, t) in self.planes.iter().enumerate() {
            let (pw, ph, bpp) = if i == 0 { (w, h, 1usize) } else { (w / 2, h / 2, if nv12 { 2 } else { 1 }) };
            let len = f.linesize(i) as usize * (ph as usize - 1) + pw as usize * bpp;
            // SAFETY: plane i holds at least linesize*(h-1)+w*bpp bytes.
            let data = unsafe { std::slice::from_raw_parts(f.data(i), len) };
            self.queue.write_texture(
                wgpu::TexelCopyTextureInfo { texture: t, mip_level: 0, origin: wgpu::Origin3d::ZERO, aspect: wgpu::TextureAspect::All },
                data,
                wgpu::TexelCopyBufferLayout { offset: 0, bytes_per_row: Some(f.linesize(i) as u32), rows_per_image: Some(ph) },
                wgpu::Extent3d { width: pw, height: ph, depth_or_array_layers: 1 },
            );
        }
        let mut views: Vec<_> = self.planes.iter().map(|t| t.create_view(&Default::default())).collect();
        if nv12 {
            views.push(self.dummy.create_view(&Default::default()));
        }
        Ok((views, if nv12 { 1 } else { 0 }))
    }

    pub fn prepare(&mut self, fr: &DecodedFrame) -> Result<slint::Image> {
        let (views, mode, w, h, _keep): (Vec<wgpu::TextureView>, u32, u32, u32, Option<wgpu::Texture>) = match &fr.payload {
            Payload::Yuv(f) => {
                let (v, m) = self.upload_cpu(f)?;
                (v, m, f.width() as u32, f.height() as u32, None)
            }
            Payload::Drm(f) => {
                let Some(vk) = self.vk.as_ref() else { bail!("Vulkan DMA-BUF import unavailable on this device") };
                let t = vk.import(&self.device, f)?;
                self.hold.push_back(f.clone());
                while self.hold.len() > 3 {
                    self.hold.pop_front();
                }
                let y = t.create_view(&wgpu::TextureViewDescriptor { aspect: wgpu::TextureAspect::Plane0, format: Some(wgpu::TextureFormat::R8Unorm), ..Default::default() });
                let uv = t.create_view(&wgpu::TextureViewDescriptor { aspect: wgpu::TextureAspect::Plane1, format: Some(wgpu::TextureFormat::Rg8Unorm), ..Default::default() });
                (vec![y, uv, self.dummy.create_view(&Default::default())], 1, f.width() as u32, f.height() as u32, Some(t))
            }
            Payload::Rgba(_) => bail!("RGBA payload given to the wgpu presenter"),
        };
        self.ensure_targets(w, h);
        let target = self.targets[self.next].clone();
        self.next = (self.next + 1) % RING;
        let mut u = [0u8; 16];
        u[0..4].copy_from_slice(&mode.to_le_bytes());
        u[4..8].copy_from_slice(&(w as f32).to_le_bytes());
        u[8..12].copy_from_slice(&(h as f32).to_le_bytes());
        self.queue.write_buffer(&self.uniform, 0, &u);
        let bg = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: None,
            layout: &self.bgl,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: wgpu::BindingResource::TextureView(&views[0]) },
                wgpu::BindGroupEntry { binding: 1, resource: wgpu::BindingResource::TextureView(&views[1]) },
                wgpu::BindGroupEntry { binding: 2, resource: wgpu::BindingResource::TextureView(&views[2]) },
                wgpu::BindGroupEntry { binding: 3, resource: wgpu::BindingResource::Sampler(&self.sampler) },
                wgpu::BindGroupEntry { binding: 4, resource: self.uniform.as_entire_binding() },
            ],
        });
        let tv = target.create_view(&Default::default());
        let mut enc = self.device.create_command_encoder(&Default::default());
        {
            let mut pass = enc.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("yuv->rgb"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &tv,
                    depth_slice: None,
                    resolve_target: None,
                    ops: wgpu::Operations { load: wgpu::LoadOp::Clear(wgpu::Color::BLACK), store: wgpu::StoreOp::Store },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
                multiview_mask: None,
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &bg, &[]);
            pass.draw(0..3, 0..1);
        }
        self.queue.submit(Some(enc.finish()));
        if self.sync {
            let _ = self.device.poll(wgpu::PollType::wait_indefinitely());
        }
        slint::Image::try_from(target).map_err(|e| anyhow!("slint::Image::try_from(wgpu::Texture): {e}"))
    }
}
