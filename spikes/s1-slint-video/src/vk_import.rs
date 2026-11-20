//! Vulkan DMA-BUF import for path (a): a VAAPI surface exported as DRM PRIME is imported as a
//! multi-planar `G8_B8R8_2PLANE_420_UNORM` VkImage (VK_EXT_external_memory_dma_buf +
//! VK_EXT_image_drm_format_modifier) and wrapped as a `wgpu::Texture` of format NV12 through
//! wgpu-hal.
//!
//! STATUS: compiles; **not exercised** on this machine (no GPU, no VAAPI). It must be validated on
//! the GPU PC (see RUN_ON_GPU.md). Known simplification: the imported image is declared to wgpu as
//! already in a shader-read state (no UNDEFINED -> SHADER_READ barrier / queue-family-foreign
//! acquire), which works on Mesa drivers in practice but is not strictly spec-conformant.

use crate::decode::DrmFrame;
use anyhow::{Context, Result, anyhow, bail};
use ash::vk;
use slint::wgpu_30::wgpu;
use std::ffi::CStr;
use wgpu::hal::api::Vulkan;

const DRM_MOD_INVALID: u64 = 0x00ff_ffff_ffff_ffff;

fn needed_extensions() -> [&'static CStr; 5] {
    [
        c"VK_KHR_external_memory_fd",
        c"VK_EXT_external_memory_dma_buf",
        c"VK_EXT_image_drm_format_modifier",
        c"VK_KHR_image_format_list",
        c"VK_KHR_sampler_ycbcr_conversion",
    ]
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}

/// Create a wgpu device (Vulkan) with the DMA-BUF import extensions enabled and hand it to Slint.
pub fn manual_config() -> Result<slint::wgpu_30::WGPUConfiguration> {
    let instance = wgpu::Instance::new(wgpu::InstanceDescriptor { backends: wgpu::Backends::VULKAN, ..wgpu::InstanceDescriptor::new_without_display_handle() });
    let adapter = block_on(instance.request_adapter(&wgpu::RequestAdapterOptions { power_preference: wgpu::PowerPreference::HighPerformance, ..Default::default() }))
        .map_err(|e| anyhow!("no Vulkan adapter: {e}"))?;
    let info = adapter.get_info();
    if !adapter.features().contains(wgpu::Features::TEXTURE_FORMAT_NV12) {
        bail!("adapter {} lacks wgpu Features::TEXTURE_FORMAT_NV12 (needs VK_KHR_sampler_ycbcr_conversion)", info.name);
    }
    let features = wgpu::Features::TEXTURE_FORMAT_NV12;
    let limits = adapter.limits();
    // SAFETY: hal adapter access; the extension list is checked against what the device supports.
    let open = unsafe {
        let hal = adapter.as_hal::<Vulkan>().ok_or_else(|| anyhow!("adapter is not Vulkan"))?;
        for e in needed_extensions() {
            if !hal.physical_device_capabilities().supports_extension(e) {
                bail!("Vulkan adapter {} lacks {}", info.name, e.to_string_lossy());
            }
        }
        hal.open_with_callback(
            features,
            &limits,
            &wgpu::MemoryHints::Performance,
            Some(Box::new(|args: wgpu::hal::vulkan::CreateDeviceCallbackArgs<'_, '_, '_>| {
                for e in needed_extensions() {
                    if !args.extensions.contains(&e) {
                        args.extensions.push(e);
                    }
                }
            })),
        )
        .map_err(|e| anyhow!("vkCreateDevice with dma-buf extensions: {e:?}"))?
    };
    // SAFETY: `open` was created from this adapter with a subset of its features.
    let (device, queue) = block_on(async {
        unsafe {
            adapter.create_device_from_hal::<Vulkan>(
                open,
                &wgpu::DeviceDescriptor { label: Some("s1-dmabuf"), required_features: features, required_limits: limits, ..Default::default() },
            )
        }
    })
    .map_err(|e| anyhow!("create_device_from_hal: {e}"))?;
    Ok(slint::wgpu_30::WGPUConfiguration::Manual { instance, adapter, device, queue })
}

pub struct VkImporter {
    _priv: (),
}

impl VkImporter {
    pub fn new(device: &wgpu::Device) -> Result<Self> {
        if !device.features().contains(wgpu::Features::TEXTURE_FORMAT_NV12) {
            bail!("device was not created with TEXTURE_FORMAT_NV12 (Slint did not use the manual DMA-BUF-capable device)");
        }
        // SAFETY: read-only query of enabled extensions.
        unsafe {
            let hal = device.as_hal::<Vulkan>().ok_or_else(|| anyhow!("device is not Vulkan"))?;
            let en = hal.enabled_device_extensions();
            for e in needed_extensions() {
                if !en.contains(&e) {
                    bail!("device lacks enabled extension {}", e.to_string_lossy());
                }
            }
        }
        Ok(Self { _priv: () })
    }

    /// Import the frame's NV12 DMA-BUF as a wgpu NV12 texture.
    pub fn import(&self, device: &wgpu::Device, f: &DrmFrame) -> Result<wgpu::Texture> {
        let d = f.desc();
        let planes = f.planes();
        if planes.len() != 2 {
            bail!("expected 2 planes (NV12), got {}", planes.len());
        }
        let obj = &d.objects[planes[0].object_index as usize];
        if planes.iter().any(|p| d.objects[p.object_index as usize].fd != obj.fd) {
            bail!("planes live in different DMA-BUF objects (disjoint import not implemented)");
        }
        if obj.format_modifier == DRM_MOD_INVALID {
            bail!("driver exported DRM_FORMAT_MOD_INVALID; modifier-less import not implemented");
        }
        let (w, h) = (f.width() as u32, f.height() as u32);
        let extent = wgpu::Extent3d { width: w, height: h, depth_or_array_layers: 1 };

        // SAFETY: raw Vulkan calls. Every handle is created from the wgpu device and either owned by
        // the returned texture (freed in the drop callback) or destroyed on the error paths.
        unsafe {
            let hal = device.as_hal::<Vulkan>().ok_or_else(|| anyhow!("device is not Vulkan"))?;
            let dev = hal.raw_device().clone();
            let inst = hal.shared_instance().raw_instance();
            let phys = hal.raw_physical_device();

            let layouts = [
                vk::SubresourceLayout { offset: planes[0].offset as u64, row_pitch: planes[0].pitch as u64, size: 0, array_pitch: 0, depth_pitch: 0 },
                vk::SubresourceLayout { offset: planes[1].offset as u64, row_pitch: planes[1].pitch as u64, size: 0, array_pitch: 0, depth_pitch: 0 },
            ];
            let mut modifier = vk::ImageDrmFormatModifierExplicitCreateInfoEXT::default().drm_format_modifier(obj.format_modifier).plane_layouts(&layouts);
            let mut ext_info = vk::ExternalMemoryImageCreateInfo::default().handle_types(vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT);
            let formats = [vk::Format::G8_B8R8_2PLANE_420_UNORM, vk::Format::R8_UNORM, vk::Format::R8G8_UNORM];
            let mut fmt_list = vk::ImageFormatListCreateInfo::default().view_formats(&formats);
            let ci = vk::ImageCreateInfo::default()
                .flags(vk::ImageCreateFlags::MUTABLE_FORMAT)
                .image_type(vk::ImageType::TYPE_2D)
                .format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
                .extent(vk::Extent3D { width: w, height: h, depth: 1 })
                .mip_levels(1)
                .array_layers(1)
                .samples(vk::SampleCountFlags::TYPE_1)
                .tiling(vk::ImageTiling::DRM_FORMAT_MODIFIER_EXT)
                .usage(vk::ImageUsageFlags::SAMPLED)
                .sharing_mode(vk::SharingMode::EXCLUSIVE)
                .initial_layout(vk::ImageLayout::UNDEFINED)
                .push_next(&mut ext_info)
                .push_next(&mut modifier)
                .push_next(&mut fmt_list);
            let image = dev.create_image(&ci, None).context("vkCreateImage (DMA-BUF, NV12)")?;

            let reqs = dev.get_image_memory_requirements(image);
            let fd_loader = ash::khr::external_memory_fd::Device::new(inst, &dev);
            let owned_fd = libc::dup(obj.fd);
            if owned_fd < 0 {
                dev.destroy_image(image, None);
                bail!("dup(dma-buf fd) failed");
            }
            let mut fd_props = vk::MemoryFdPropertiesKHR::default();
            if let Err(e) = fd_loader.get_memory_fd_properties(vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT, owned_fd, &mut fd_props) {
                libc::close(owned_fd);
                dev.destroy_image(image, None);
                bail!("vkGetMemoryFdPropertiesKHR: {e:?}");
            }
            let mem_props = inst.get_physical_device_memory_properties(phys);
            let bits = reqs.memory_type_bits & fd_props.memory_type_bits;
            let Some(type_index) = (0..mem_props.memory_type_count).find(|i| bits & (1 << i) != 0) else {
                libc::close(owned_fd);
                dev.destroy_image(image, None);
                bail!("no compatible memory type for the DMA-BUF (image bits {:#x}, fd bits {:#x})", reqs.memory_type_bits, fd_props.memory_type_bits);
            };
            let mut import = vk::ImportMemoryFdInfoKHR::default().handle_type(vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT).fd(owned_fd);
            let mut dedicated = vk::MemoryDedicatedAllocateInfo::default().image(image);
            let ai = vk::MemoryAllocateInfo::default().allocation_size(reqs.size).memory_type_index(type_index).push_next(&mut import).push_next(&mut dedicated);
            let memory = match dev.allocate_memory(&ai, None) {
                Ok(m) => m, // the fd is now owned by the driver
                Err(e) => {
                    libc::close(owned_fd);
                    dev.destroy_image(image, None);
                    bail!("vkAllocateMemory (import dma-buf): {e:?}");
                }
            };
            if let Err(e) = dev.bind_image_memory(image, memory, 0) {
                dev.free_memory(memory, None);
                dev.destroy_image(image, None);
                bail!("vkBindImageMemory: {e:?}");
            }

            let hal_desc = wgpu::hal::TextureDescriptor {
                label: Some("vaapi-dmabuf-nv12"),
                size: extent,
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format: wgpu::TextureFormat::NV12,
                usage: wgpu::TextureUses::RESOURCE,
                memory_flags: wgpu::hal::MemoryFlags::empty(),
                view_formats: vec![],
            };
            let dev2 = dev.clone();
            let hal_tex = hal.texture_from_raw(
                image,
                &hal_desc,
                Some(Box::new(move || {
                    dev2.destroy_image(image, None);
                    dev2.free_memory(memory, None);
                })),
                wgpu::hal::vulkan::TextureMemory::External,
            );
            drop(hal);
            Ok(device.create_texture_from_hal::<Vulkan>(
                hal_tex,
                &wgpu::TextureDescriptor {
                    label: Some("vaapi-dmabuf-nv12"),
                    size: extent,
                    mip_level_count: 1,
                    sample_count: 1,
                    dimension: wgpu::TextureDimension::D2,
                    format: wgpu::TextureFormat::NV12,
                    usage: wgpu::TextureUsages::TEXTURE_BINDING,
                    view_formats: &[],
                },
                wgpu::TextureUses::RESOURCE,
            ))
        }
    }
}
