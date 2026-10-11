# README 图片

- `icon.png`：用 Icon Composer 的 `ictool` 从 `Tower/AppIcon.icon` 渲染的图标（带 Liquid Glass 效果），再加上 Mac 风格的边距、圆角和阴影，256 像素。
- `clients/*.png`：README 里的客户端图标，取自 `Tower/Assets.xcassets/Client*.imageset/`，缩放到 120 像素并按 iOS 图标圆角裁切；权利归各客户端所有，见 [第三方声明](../../THIRD-PARTY-NOTICES.md#客户端-app-图标)。
- `iphone-1.jpg` 至 `iphone-5.jpg`、`mac-3.jpg`：App Store 宣传图的压缩版，2026-10-11 制作。

宣传图里的界面是塔台的真实截图，用 Debug 专用的 `--demo --showcase` 示例数据拍摄，服务器均为 `example.com`。界面内容没有修改或重绘；外面的标题文字、背景和设备外壳是后期合成的，设备外壳为自绘，没有使用 Apple 的设备素材。拍摄方法见 [DEVELOPMENT.md](../DEVELOPMENT.md#app-store-截图)。
