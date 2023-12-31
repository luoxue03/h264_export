 
Ref:
   * http://blog.csdn.net/jasonhwang/article/details/7359095
   * https://github.com/mariahyang/h264_export

抓取一个包含H.264 Payload RTP包的SIP会话或RTSP会话后，用Wireshark的Play功能只能播放声音，不能播放视频。把RTP payload直接导出成文件后也是不能直接播放的，因为H.264 over RTP封包是符合RFC3984规范的，必须按照该规范把H.264数据取出来后，组成NALU，放到avi/mp4或裸码流文件等容器里后才能播放。

这个wireshark插件，可以在打开包含H.264码流的抓包后，选菜单“Tools->Export H264 to file [HQX's plugins]”后，把抓包文件里的H.264码流自动导出到抓包文件所在目录（工作目录）里，名为`from_<RTP流源ip>_<RTP流源端口>_to_<RTP流目的ip>_<RTP流目的端口>.264`的264裸码流文件里。（文件格式为每个NALU前加0x00000001分隔符）。

本程序可以识别RFC3984里提到的三种H.264 over RTP封装，分别是Single NALU（一个RTP含一个NALU）、STAP-A（一个RTP包含多个NALU）、FU-A（一个NALU分布到多个RTP包）三种封装格式，且会自动把SPS和PPS放到裸码流文件头部。

使用须知:
把代码保存成h264_export.lua文件，放到wireshark安装目录下，然后修改wireshark安装目录下的init.lua文件：
1. 若有`disable_lua = true`这样的行，则注释掉；
2. 在文件末加入`dofile("h264_export.lua")`
3. 使用管理员权限重新打开Wireshark
另外，264裸码流文件一般播放器不一定能播放，推荐使用ffmpeg的ffplay播放，或用ffmpeg转成通用文件格式播放。
建议使用PotPlayer,在安装时安装H246插件

版本:
* 2014年升级版，支持排序、丢弃不完整帧，注意生成的文件from...在抓拍文件相同的目录
* 2015 升级版