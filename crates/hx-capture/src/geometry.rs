/// Width and height in pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

impl Size {
    pub const fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }

    pub const fn pixels(self) -> u64 {
        self.width as u64 * self.height as u64
    }
}

/// An axis-aligned rectangle in screen pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub const fn full(size: Size) -> Self {
        Self::new(0, 0, size.width, size.height)
    }

    pub const fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    pub fn area(&self) -> u64 {
        self.width as u64 * self.height as u64
    }

    /// Smallest rectangle containing both. An empty operand is ignored.
    pub fn union(self, other: Rect) -> Rect {
        if self.is_empty() {
            return other;
        }
        if other.is_empty() {
            return self;
        }
        let x0 = self.x.min(other.x);
        let y0 = self.y.min(other.y);
        let x1 = (self.x + self.width as i32).max(other.x + other.width as i32);
        let y1 = (self.y + self.height as i32).max(other.y + other.height as i32);
        Rect::new(x0, y0, (x1 - x0) as u32, (y1 - y0) as u32)
    }

    /// Clip to `0..size`; may return an empty rectangle.
    pub fn clip(self, size: Size) -> Rect {
        let x0 = self.x.clamp(0, size.width as i32);
        let y0 = self.y.clamp(0, size.height as i32);
        let x1 = (self.x + self.width as i32).clamp(0, size.width as i32);
        let y1 = (self.y + self.height as i32).clamp(0, size.height as i32);
        Rect::new(x0, y0, (x1 - x0) as u32, (y1 - y0) as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_and_clip() {
        let a = Rect::new(10, 10, 20, 20);
        let b = Rect::new(100, 5, 10, 10);
        assert_eq!(a.union(b), Rect::new(10, 5, 100, 25));
        assert_eq!(a.union(Rect::new(0, 0, 0, 0)), a);
        assert_eq!(
            Rect::new(-5, -5, 20, 20).clip(Size::new(10, 10)),
            Rect::new(0, 0, 10, 10)
        );
        assert!(Rect::new(50, 50, 5, 5).clip(Size::new(10, 10)).is_empty());
    }
}
