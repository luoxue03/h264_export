-- Dump RTP h.264 payload to raw h.264 file (*.264)
-- According to RFC3984 to dissector H264 payload of RTP to NALU, and write it
-- to from<sourceIp_sourcePort>to<dstIp_dstPort>.264 file. By now, we support single NALU,
-- STAP-A and FU-A format RTP payload for H.264.
-- You can access this feature by menu "Tools->Export H264 to file [HQX's plugins]"
-- Author: Huang Qiangxiong (qiangxiong.huang@gmail.com)
-- change log:
--      2012-03-13
--          Just can play
------------------------------------------------------------------------------------------------
do
    -- for geting h264 data (the field's value is type of ByteArray)
    local f_h264 = Field.new("h264") 
    -- menu action. When you click "Tools->Export H264 to file [HQX's plugins]" will run this function
    local function export_h264_to_file()
        -- window for showing information
        local tw = TextWindow.new("Export H264 to File Info Win")
        local pgtw = ProgDlg.new("Export H264 to File Process", "Dumping H264 data to file...")
        
        -- add message to information window
        function twappend(str)
            tw:append(str)
            tw:append("\n")
        end
        
        -- running first time for counting and finding sps+pps, second time for real saving
        local first_run = true 
        -- variable for storing rtp stream and dumping parameters
        local stream_infos = {}
        -- trigered by all h264 packats
        local my_h264_tap = Listener.new(tap, "h264")
        
        -- get rtp stream info by src and dst address
        function get_stream_info(pinfo)
            local key = "from_" .. tostring(pinfo.src) .. "_" .. tostring(pinfo.src_port) .. "to" .. tostring(pinfo.dst) .. "_" .. tostring(pinfo.dst_port)
            local stream_info = stream_infos[key]
            if not stream_info then -- if not exists, create one
                stream_info = { }
                stream_info.filename = key.. ".264"
                stream_info.file = io.open(stream_info.filename, "wb")
                stream_info.counter = 0 -- counting h264 total NALUs
                stream_info.counter2 = 0 -- for second time running
                stream_infos[key] = stream_info
                twappend("Ready to export H.264 data (RTP from " .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) 
                         .. " to " .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) .. " to file:\n         [" .. stream_info.filename .. "] ...\n")
            end
            return stream_info
        end
        
        -- write a NALU or part of NALU to file.
        function write_to_file(stream_info, str_bytes, begin_with_nalu_hdr)
            if first_run then
                stream_info.counter = stream_info.counter + 1
                
                if begin_with_nalu_hdr then
                    -- save SPS or PPS
                    local nalu_type = bit.band(str_bytes:byte(0,1), 0x1F)
                    if not stream_info.sps and nalu_type == 7 then
                        stream_info.sps = str_bytes
                    elseif not stream_info.pps and nalu_type == 8 then
                        stream_info.pps = str_bytes
                    end
                end
                
            else -- second time running
                if stream_info.counter2 == 0 then
                    -- write SPS and PPS to file header first
                    if stream_info.sps then
                        stream_info.file:write("\00\00\00\01")
                        stream_info.file:write(stream_info.sps)
                    else
                        twappend("Not found SPS for [" .. stream_info.filename .. "], it might not be played!\n")
                    end
                    if stream_info.pps then
                        stream_info.file:write("\00\00\00\01")
                        stream_info.file:write(stream_info.pps)
                    else
                        twappend("Not found PPS for [" .. stream_info.filename .. "], it might not be played!\n")
                    end
                end
            
                if begin_with_nalu_hdr then
                    -- *.264 raw file format seams that every nalu start with 0x00000001
                    stream_info.file:write("\00\00\00\01")
                end
                stream_info.file:write(str_bytes)
                stream_info.counter2 = stream_info.counter2 + 1
                
                if stream_info.counter2 == stream_info.counter then
                    stream_info.file:flush()
                    twappend("File [" .. stream_info.filename .. "] generated OK!\n")
                end
                -- update progress window's progress bar
                if stream_info.counter > 0 then pgtw:update(stream_info.counter2 / stream_info.counter) end
            end
        end
        
        -- read RFC3984 about single nalu/stap-a/fu-a H264 payload format of rtp
        -- single NALU: one rtp payload contains only NALU
        function process_single_nalu(stream_info, h264)
            write_to_file(stream_info, h264:tvb()():string(), true)
        end
        
        -- STAP-A: one rtp payload contains more than one NALUs
        function process_stap_a(stream_info, h264)
            local h264tvb = h264:tvb()
            local offset = 1
            repeat
                local size = h264tvb(offset,2):uint()
                write_to_file(stream_info, h264tvb(offset+2, size):string(), true)
                offset = offset + 2 + size
            until offset >= h264tvb:len()
        end
        
        -- FU-A: one rtp payload contains only one part of a NALU (might be begin, middle and end part of a NALU)
        function process_fu_a(stream_info, h264)
            local h264tvb = h264:tvb()
            local fu_idr = h264:get_index(0)
            local fu_hdr = h264:get_index(1)
            if bit.band(fu_hdr, 0x80) ~= 0 then
                -- start bit is set then save nalu header and body
                local nalu_hdr = bit.bor(bit.band(fu_idr, 0xE0), bit.band(fu_hdr, 0x1F))
                write_to_file(stream_info, string.char(nalu_hdr), true)
            else
                -- start bit not set, just write part of nalu body
            end
            write_to_file(stream_info, h264tvb(2):string(), false)
        end
        
        -- call this function if a packet contains h264 payload
        function my_h264_tap.packet(pinfo,tvb)
            local h264s = { f_h264() } -- using table because one packet may contains more than one RTP
            for i,h264_f in ipairs(h264s) do
                if h264_f.len < 2 then
                    return
                end
                local h264 = h264_f.value   -- is ByteArray
                local hdr_type = bit.band(h264:get_index(0), 0x1F)
                local stream_info = get_stream_info(pinfo)
                
                if hdr_type > 0 and hdr_type < 24 then
                    -- Single NALU
                    process_single_nalu(stream_info, h264)
                elseif hdr_type == 24 then
                    -- STAP-A Single-time aggregation
                    process_stap_a(stream_info, h264)
                elseif hdr_type == 28 then
                    -- FU-A
                    process_fu_a(stream_info, h264)
                else
                    twappend("Error: unknown type=" .. hdr_type .. " ; we only know 1-23(Single NALU),24(STAP-A),28(FU-A)!")
                end
            end
        end
        
        -- close all open files
        function close_all_files()
            if stream_infos then
                for id,stream in pairs(stream_infos) do
                    if stream and stream.file then
                        stream.file:close()
                        stream.file = nil
                    end
                end
            end
        end
        
        function my_h264_tap.reset()
            -- do nothing now
        end
        
        function remove()
            close_all_files()
            my_h264_tap:remove()
        end
        
        tw:set_atclose(remove)
        
        -- first time it runs for counting h.264 packets and finding SPS and PPS
        retap_packets()
        first_run = false
        -- second time it runs for saving h264 data to target file.
        retap_packets()
        -- close progress window
        pgtw:close()
    end
    
    -- Find this feature in menu "Tools->"Export H264 to file [HQX's plugins]""
    register_menu("Export H264 to file [HQX's plugins]", export_h264_to_file, MENU_TOOLS_UNSORTED)
end