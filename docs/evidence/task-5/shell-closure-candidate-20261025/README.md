# 真实 shell 候选的固定公共材料核对

2026-10-25 UTC08:31:52 的[只读记录](metadata.json)核对本机 dash、libc 与加载器：三份 root0:0、单链接、无 xattr 的普通 ELF 文件共2,575,328B；依赖声明为 dash→libc.so.6→ld-linux-x86-64.so.2。固定 readelf/dpkg-query 工具及包版本、许可通知输入的大小/SHA 一并记录，没有复制材料、执行 shell/攻击、下载、安装、打包或创建资源。

这只是已安装材料的身份与 ELF 声明核对。没有验证发布者签名或原始 deb 哈希，也没有证明 guest ABI、完整场景或加入 Go payload 后实际适配32MiB。未来打包须另审查并以普通文件生成精确 guest 路径，保留相应通知；不隐含准许宿主别名或通用依赖解析。Task5 的42格仍全部未执行。

控制器 v1 在读取 dpkg-query 后的完整 stat 比较处 AssertionError，未创建输出目录或资源；原脚本保留为 `controller-readonly-v1.py`。v2 只将稳定性比较收窄为 dev/inode/mode/owner/nlink/size/mtime/ctime，排除读取可更新的 atime；其余材料与限制不变，实际通过。该失败不冒充包/ABI拒绝或产品回归。
