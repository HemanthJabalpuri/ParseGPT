#!/usr/bin/env lua5.3
-- Parse Primary GPT & Partition Entries Array from gpt files
-- both 512 and 4096-byte sector sizes are supported
-- Tested gpt.bin of
--   * Motorola Nexus 6 (512-byte sector disk)
--   * Moto G52 (4096-byte sector disk)

-- LBA 0 Protective MBR
-- LBA 1 Primary GPT Header
-- LBA 2 to LBA n having Partition Entries that makes 16KiB total

GPT_SIGNATURE = "EFI PART"

guids = {
-- AOSP
  ["77036cd4-03d5-42bb-8ed1-37e5a88baa34"] = "Inactive Slot partition",
  ["82acc91f-357c-4a68-9c8f-689e1b1a23a1"] = "Android misc 1",
  ["5594c694-c871-4b5f-90b1-690a6f68e0f7"] = "Android cache",
  ["24d0d418-d31d-4d8d-ac2c-4d4305188450"] = "dtbo",
  ["4b7a15d6-322c-42ac-8110-88b7da0c5d77"] = "vbmeta",
  ["1344859d-3a6a-4c14-a316-9e696b3a5400"] = "vbmeta_system",
  ["20117f86-e985-4357-b9ee-374bc1d8487d"] = "Android boot 2/logo", -- ginna uses this for both boot and logo
  ["97d7b011-54da-4835-b3c4-917ad6e73d74"] = "Android system 2/vendor/oem/super", -- athene uses for both system and oem. ginna, hanoip uses this for super
  ["89a12de1-5e41-4cb3-8b4c-b1441eb5da38"] = "super",
  ["1b81e7e6-f50d-419b-a739-2aeef8da3335"] = "Android user data/devinfo", -- ginna uses this for both userdata and devinfo
  ["d504d6db-fa92-4853-b59e-c7f292e2ea19"] = "vendor_boot/recovery", -- hiphi uses this for recovery
  ["9d72d4e4-9958-42da-ac26-bea7a90b0434"] = "Android recovery 2",
  ["a877b68d-0518-3416-921f-db32d65e3d54"] = "metadata",
-- Qualcomm
  ["20a0c19c-286a-42fa-9ce7-f64c3226a794"] = "Android DDR",
-- Qualcomm Singleimage (bootloader)
  ["bd6928a1-4ce0-a038-4f3a-1495e3eddffb"] = "abl",
  ["400ffdcd-22e0-47e7-9a23-f16ed9382388"] = "Android APPSBL/uefi", -- hiphi uses for uefi
  ["d69e90a5-4cab-0071-f6df-ab977f141a7f"] = "aop",
  ["dea0ba2c-cbdd-4805-b4f9-f428251c3e98"] = "Android SBL1/sbl1bak/xbl", -- Nexus 6 uses this for both sbl1 and sbl1bak
  ["5a325ae4-4276-b66d-0add-3494df27706a"] = "xbl_config",
  ["e1a6a689-0c8d-4cc6-b4e8-55a4320fbd8a"] = "Android QHEE/hyp",
  ["a053aa7f-40b8-4b1c-ba08-2f68ac71a4f4"] = "Android QSEE/tz",
  ["f65d4b16-343d-4e25-aafc-be99b6556a6d"] = "devcfg",
  ["02db45fe-ad1b-4cb6-aecc-0042c637defa"] = "storesec",
  ["be8a7e08-1b7a-4cae-993a-d5b7fb55b3c2"] = "uefisecapp",
  ["21d1219f-2ed1-4ab4-930a-41a16ae75f7f"] = "qupfw",
  ["d05e0fc0-ffee-1fee-115d-eba7ab1ef00d"] = "prov",
  ["098df793-d712-413d-9d4e-89d711772228"] = "Android RPM/syscfg", -- ginna uses this both rpm and syscfg (syscfg not comes in singleimage.bin)
  ["a11d2a7c-d82a-4c2f-8a01-1805240e6626"] = "keymaster",
  ["73471795-ab54-43f9-a847-4f72ea5cbef5"] = "cmnlib",
  ["8ea64893-1267-4a1b-947c-7c362acaad2c"] = "cmnlib64",
  ["1e8615bd-6d8c-41ad-b3ea-50e8bf40e43f"] = "cpucp/vendor_boot (other)", -- berlin, hiphi uses this for both cpucp and vendor_boot, ibiza uses for vendor_boot
  ["cb74ca22-2f0d-4b82-a1d6-c4213f348d73"] = "shrm", -- hiphi, berlin
  ["846c6f05-eb46-4c0a-a1a3-3648ef3f9d0e"] = "multiimgqti", -- hanoip
  ["e126a436-757e-42d0-8d19-0f362f7a62b8"] = "multiimgoem", -- hanoip
  ["9fbf2575-b96c-4448-b520-a570b3560375"] = "spss", -- hiphi, nio
  ["0382f197-e41f-4e84-b18b-0b564aead875"] = "xbl_ramdump", -- hiphi
  ["3d12f234-c882-4b46-a20c-17d52c8fc03d"] = "aop_config", -- hiphi
-- Qualcomm Firmware
  ["ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"] = "modem/dsp/sbl1bak/padA/padB/padC/padD/mmi_misc/mota", -- ginna uses this for both modem, dsp and mota. albus uses for sbl1bak. ali uses mmi_misc
  ["7efe5010-2a1a-4a1a-b8bc-990257813512"] = "dsp",
  ["6cb747f1-c2ef-4092-add0-ca39f79c7af4"] = "bluetooth",
  ["ebbeadaf-22c9-e33b-8f5d-0e81686a68cb"] = "Android modem ST1(MODEM FS1)",
  ["0a288b1f-22c9-e33b-8f5d-0e81686a68cb"] = "Android modem ST2(MODEM FS2)",
  ["638ff8e2-22c9-e33b-8f5d-0e81686a68cb"] = "Android FSG 1(MODEM FS Golden Copy)",
  ["57b90a16-22c9-e33b-8f5d-0e81686a68cb"] = "Android FSC(MODEM FS Cookie)/modemst1", -- hiphi uses for modemst1
  ["2290be64-22c9-e33b-8f5d-0e81686a68cb"] = "mdm1m9kefs1(Fusion Modem FS1)", -- Nexus 6, nio
  ["346c26d1-22c9-e33b-8f5d-0e81686a68cb"] = "mdm1m9kefs2(Fusion Modem FS2)", -- Nexus 6, nio
  ["bf64fb9c-22c9-e33b-8f5d-0e81686a68cb"] = "mdm1m9kefs3(Fusion Modem FS Golden Copy)", -- Nexus 6. nio for mdm1m9kefs3_a
  ["5cb43a64-22c9-e33b-8f5d-0e81686a68cb"] = "mdm1m9kefsc(Fusion Modem FS Cookie)", -- Nexus 6, nio
-- per-device configuration
  ["459abd04-e62c-11e0-b630-001111ea6a40"] = "cid",
  ["91b72d4d-71e0-4cbf-9b8e-236381cff17a"] = "frp/config", -- athene uses for both frp and config
  ["b2d77ec0-8957-11e5-af63-feff819cdc9f"] = "hw",
  ["6c95e238-e343-4ba8-b489-8681ed22ad0b"] = "Android persist/persist2/prodpersist",
  ["1dd40d18-e3c8-11e0-a48c-c75729cde6e5"] = "utags",
  ["65addcf4-0c5c-4d9a-ac2d-d90b5cbfcd03"] = "Android device info",
  ["40aef62a-e62c-11e0-aec5-001111ea6a40"] = "sp",
-- Misc
  ["2c86e742-745e-4fdd-bfd8-b6a7ac638772"] = "Android SSD",
  ["c490f39c-9538-40ec-b320-efa23cc6cfcd"] = "utags backup/secdata backup", -- hiphi uses for secdata backup
  ["56465e10-e62c-11e0-85d9-001111ea6a40"] = "kpan",
  ["c63d32d8-c880-4f28-b4d6-27f5542324ca"] = "carrier",
  ["8a749857-c804-4041-8d6e-39f668f1d007"] = "dhob/mdm1dhob", -- Nexus 6 uses this for mdm1dhob
  ["ed9e8101-05fa-46b7-82aa-8d58770d200b"] = "Android MSADP",
  ["33ca947a-009b-11e2-abd8-d7d9cfa8b5aa"] = "logs", -- Nexus 6, griffin
  ["303e6ac3-af15-4c54-9e9b-d9a8fbecf401"] = "Android SEC", -- Nexus 6, griffin
  ["bc0330eb-3410-4951-a617-03898dbe3372"] = "logfs",
  ["e6e98da2-e22a-4d12-ab33-169e7deaa507"] = "Android APDP",
  ["e42e2b4c-33b0-429b-b1ef-d341c547022c"] = "spunvm",
  ["10a0c19c-516a-5444-5ce3-664c3226a794"] = "Android limits",
  ["165bd6bc-9250-4ac8-95a7-a93f4a440066"] = "uefivarstore",
  ["ad99f201-dc71-4e30-9630-e19eef553d1b"] = "logo",
  ["e8b7cf6e-5694-4627-8a2a-899b09f2dbea"] = "keymaster (other)", -- albus, athene
  ["cd3f20e4-637a-11e1-bdf4-a384200477af"] = "abootbak", -- albus
  ["e4b09cf6-33c3-4957-8d43-7bc2bb081648"] = "cmnlibbak", -- griffin, albus
  ["1f16d443-b557-4585-bd40-6aba70eb55f0"] = "cmnlib64bak", -- griffin, albus
  ["480953fa-6379-11e1-932e-37e5e895eac2"] = "tzbak", -- Nexus 6, albus
  ["5d557142-faac-4de5-85f3-6e9773f5fe30"] = "provbak", -- griffin, albus
  ["5f1553be-6379-11e1-9247-2b97cf74ad48"] = "rpmbak", -- albus
  ["ab332e47-f73a-4df9-be67-421d9cbf393b"] = "devcfgbak", -- griffin, albus
  ["2439a611-b977-4924-963e-1a401376ae7e"] = "keymasterbak", -- griffin, albus
  ["4114b077-005d-4e12-ac8c-b493bda684fb"] = "dip", -- griffin, albus
  ["11406f35-1173-4869-807b-27df71802812"] = "Android DPO", -- griffin, albus
  ["7db6ac55-ecb5-4e02-80da-4d335b973332"] = "oem", -- payton, ali
  ["76cfc7ef-039d-4e2c-b81e-4dd8c2cb2a93"] = "secdata", -- ibiza, hiphi
  ["988a98c9-2910-4123-aaec-1cf6b1bc28f9"] = "metadata (other)", -- ibiza
  ["545d3707-8329-40e8-8b5e-3e554cbdc786"] = "limits-cdsp", -- hiphi, berlin, nio
  ["478dea49-abe9-4391-85df-bf4bc2eb08f6"] = "tzsc", -- berlin, hiphi
  ["358740b1-34bd-4e4c-9656-3454f0a8fdd9"] = "qmcs", -- berlin, hiphi
  ["e396d1ea-0eac-4241-bb82-7150645cfc45"] = "rtice", -- berlin, hiphi
  ["6a716f7c-b68a-4977-9afe-452be73594a6"] = "connsec", -- berlin, hiphi
  ["c00eef24-7709-43d6-9799-dd2b411e7a3c"] = "Android PMIC", -- griffin, payton, nash
  ["de7d4029-0f5b-41c8-ae7e-f6c023a02b33"] = "Android keystore", -- Pixel 4, hanoip
  ["fde1604b-d68b-4bd4-973d-962ae7a1ed88"] = "pad3/pad4",
-- Pixel 4
  ["5af80809-aabb-4943-9168-cdfc38742598"] = "klog/logdump",
  ["a19f205f-ccd8-4b6d-8f1e-2d9bc24cffb1"] = "Android CDT",
  ["17911177-c9e6-4372-933c-804b678e666f"] = "imagefv",
  ["97745aba-135a-44c3-9adc-05616173c24c"] = "toolsfv",
  ["dd2c14a6-1b2d-4ab3-93d6-f4fe56828396"] = "super (Pixel)",
  ["3be396c2-ac1b-4ef9-ade2-c7a7cf74acd9"] = "vbmeta_system (Pixel)",
-- Rare
  ["665fe2a8-2f28-44b7-b12d-e89eec9ee9f7"] = "vm-keystore", -- ibiza
  ["c9bb2aa8-af8f-49b3-b723-a890a2c8e6d3"] = "vm-data", -- ibiza
  ["edb8145e-3b2c-11e7-beb6-07bed6e25e30"] = "vendor", -- ali
  ["f7eecb66-781a-439a-8955-70e12ed4a7a0"] = "xbl_sc_logs", -- hiphi
  ["4fcf1392-e62c-11e0-9065-001111ea6a40"] = "clogo/logo (other)", -- Nexus 6, griffin for logo (other). athene use for both
  ["433ee193-1a8e-4d35-860f-ff66676af52b"] = "mdmddr", -- nio
  ["2c7c5832-fcf1-11e6-b70a-9b9b1abdc5ce"] = "dto", -- payton, nash
  ["e4be69bf-300e-42a1-8a49-a5ad554ee25d"] = "logfs (other)", -- payton
  ["f27df0f0-47dd-11e1-b86c-0800200c9a66"] = "customize", -- griffin, athene
  ["2426c1c8-07d8-38bf-93d0-0319fa53e85e"] = "hypbak", -- griffin, nash, athene
  ["1a20da74-8a5f-4ce4-8194-cff90a6aa6e8"] = "carrier (other)", -- griffin
  ["4f772165-0f3c-4ba3-bbcb-a829e9c969f9"] = "keymaster (other2)", -- griffin
  ["c1be0c31-8958-4f7b-b682-9ce2aebd89d5"] = "oem (other2)", -- griffin
  ["9f234b5b-0efb-4313-8e4c-0af1f605536b"] = "abl_b/abootbak", -- griffin for abootbak, nash for abl_b
  ["b7804414-8e65-4a1d-93fd-9d9bf5621306"] = "rpm_b/rpmbak", -- griffin for rpmbak. nash uses rpm_b
  ["c832ea16-8b0d-4398-a67b-ebb30ef98e7e"] = "tz_b/tzbak", -- griffin uses for tzbak, nash uses for tz_b
  ["d9bd7cd9-b1ba-4f3b-a6ce-0e348a1116e9"] = "pmic_b/pmicbak", -- griffin uses for pmicbak. nash uses pmic_b
  ["c7ce455c-fcf1-11e6-9d22-0f622cac43ad"] = "dto_b", -- nash
  ["0b814b23-7f07-4e23-a99a-62d7b7a3224c"] = "storesec_b", -- nash
  ["a67e2b18-1150-11e4-9f69-b2227cce2b54"] = "metadata (other2)", -- Nexus 6
  ["de134a00-2702-11e4-a8d1-c74c90a2e3d4"] = "keystore (other)", -- Nexus 6
  ["a881cfaf-5859-375f-9061-76b143df8804"] = "frp (other)", -- Nexus 6
  ["66acb577-f65d-3c31-8937-00babeadea30"] = "oem (other)", -- Nexus 6
  ["3b2e48f4-e62c-11e0-9ab6-001111ea6a40"] = "mdm1hob", -- Nexus 6
  ["d4e0d938-b7fa-48c1-9d21-bc5ed5c4b203"] = "Android WDOG debug/sdi", -- Nexus 6
  ["a09c9086-63ea-4c80-9d5c-209989625a69"] = "versions", -- Nexus 6
  ["6c5431bc-27ee-11e4-b8aa-003048de1c62"] = "padC", -- Nexus 6
-- Android Google Source (# sgdisk --list-types)
  ["2568845D-2332-4675-BC39-8FA5A4748D15"] = "-Android bootloader",
  ["114EAFFE-1552-4022-B26E-9B053604CF84"] = "-Android bootloader 2",
  ["49A4D17F-93A3-45C1-A0DE-F50B2EBE2599"] = "-Android boot 1",
  ["4177C722-9E92-4AAB-8644-43502BFD5506"] = "-Android recovery 1",
  ["EF32A33B-A409-486C-9141-9FFB711F6266"] = "-Android misc",
  ["20AC26BE-20B7-11E3-84C5-6CFDB94711E9"] = "-Android metadata",
  ["38F428E6-D326-425D-9140-6E0EA133647C"] = "-Android system 1",
  ["A893EF21-E428-470A-9E55-0668FD91A2D9"] = "-Android cache",
  ["DC76DDA9-5AC1-491C-AF42-A82591580C0D"] = "-Android data",
  ["EBC597D0-2053-4B15-8B64-E0AAC75F4DB1"] = "-Android persistent",
  ["8F68CC74-C5E5-48DA-BE91-A0C8C15E9C80"] = "-Android factory",
  ["767941D0-2085-11E3-AD3B-6CFDB94711E9"] = "-Android fastboot/tertiary",
  ["AC6D7924-EB71-4DF8-B48D-E267B27148FF"] = "-Android OEM",
  ["C5A0AEEC-13EA-11E5-A1B1-001E67CA0C3C"] = "-Android vendor",
  ["BD59408B-4514-490D-BF12-9878D963F378"] = "-Android config",
  ["9FDAA6EF-4B3F-40D2-BA8D-BFF16BFB887B"] = "-Android factory (alt)",
  ["19A710A2-B3CA-11E4-B026-10604B889DCF"] = "-Android meta",
  ["193D1EA4-B3CA-11E4-B075-10604B889DCF"] = "-Android EXT",
  ["8C6B52AD-8A9E-4398-AD09-AE916E53AE2D"] = "-Android SBL2",
  ["05E044DF-92F1-4325-B69E-374A82E97D6E"] = "-Android SBL3",
  ["66C9B323-F7FC-48B6-BF96-6F32E335A428"] = "-Android RAM Dump",
  ["E2802D54-0545-E8A1-A1E8-C7A3E245ACD4"] = "-Android misc 2",
  ["2013373E-1AC4-4131-BFD8-B6A7AC638772"] = "-Android FSG 2",
  ["323EF595-AF7A-4AFA-8060-97BE72841BB9"] = "-Android encrypt",
  ["45864011-CF89-46E6-A445-85262E065604"] = "-Android EKSST",
  ["8ED8AE95-597F-4C8A-A5BD-A7FF8E4DFAA9"] = "-Android RCT",
  ["DF24E5ED-8C96-4B86-B00B-79667DC6DE11"] = "-Android spare1",
  ["7C29D3AD-78B9-452E-9DEB-D098D542F092"] = "-Android spare2",
  ["379D107E-229E-499D-AD4F-61F5BCF87BD4"] = "-Android spare3",
  ["0DEA65E5-A676-4CDF-823C-77568B577ED5"] = "-Android spare4",
  ["4627AE27-CFEF-48A1-88FE-99C3509ADE26"] = "-Android raw resources",
  ["86A7CB80-84E1-408C-99AB-694F1A410FC7"] = "-Android FOTA",
  ["98523EC6-90FE-4C67-B50A-0FC59ED6F56D"] = "-LG (Android) advanced flasher",
  ["2644BCC0-F36A-4792-9533-1738BED53EE3"] = "-Android PG1FS",
  ["DD7C91E9-38C9-45C5-8A12-4A80F7E14057"] = "-Android PG2FS",
  ["7696D5B6-43FD-4664-A228-C563C4A1E8CC"] = "-Android board info",
  ["0D802D54-058D-4A20-AD2D-C7A362CEACD4"] = "-Android MFG",
}

pos = 0 -- file pointer

function seek(off)
  pos = off
end

function getOff()
  return pos
end

function read(n)
  bytes = dat:sub(pos+1, pos+n)
  pos = pos + n
  return bytes
end

function find(str)
  local addr, j
  addr, j = dat:find(str)
  if addr then
    return addr - 1
  end
  return addr
end

function getString(n)
  local dat = read(n)
  return dat:gsub("\x00", "")
end

function getLong()
  local long = { string.unpack("I8", read(8), 1) }
  return long[1]
end

function getInt()
  local int = { string.unpack("I4", read(4), 1) }
  return int[1]
end

function b2hex(dat)
  return (dat:gsub('.', function (c) return string.format('%02x', c:byte()) end))
end

function n2hex(num)
  return string.format("%x", num)
end

function splitbyte(input)
  local byte, p, flags = string.byte(input), 128, {false,false,false,false,false,false,false,false}
  for i=1,8 do
    if byte >= p then
      flags[i], byte = true, byte - p
    end
    p = p / 2
  end
  return flags
end

function crc32(str)
  local poly = 0xedb88320
  local crc = 2 ^ 32 - 1
  for i = 1, #str do
    crc = crc ~ str:byte(i)
    for j = 1, 8 do
      if crc & 1 ~= 0 then
        crc = (crc >> 1) ~ poly
      else
        crc = crc >> 1
      end
    end
  end
  crc = crc ~ 0xffffffff
  if crc < 0 then
    crc = crc + 2 ^ 32
  end
  return crc
end

function getGuidtype(guid)
  found=nil
  for k,v in pairs(guids) do
    if k:lower() == guid then found=v; break; end
  end
  if found then return guid .. " (" .. found .. ")"
  else return guid
  end
end

function getGUID(bytes)
  time_low = string.format("%08x", string.unpack("<I4", bytes, 1))
  time_mid = string.format("%04x", string.unpack("<H", bytes, 5))
  time_hi_and_version = string.format("%04x", string.unpack("<H", bytes, 7))
  clock_seq_hi = b2hex(bytes:sub(9, 9))
  clock_seq_low = b2hex(bytes:sub(10, 10))
  node = b2hex(bytes:sub(11, 16))
  guid = string.format("%s-%s-%s-%s%s-%s", time_low, time_mid,
         time_hi_and_version, clock_seq_hi, clock_seq_low, node)
  return getGuidtype(guid)
end

function get_unit(bytes)
  local kb = 1024
  local mb = 1024 * kb
  local gb = 1024 * mb
  local tb = 1024 * gb
  if bytes >= tb then
    return (bytes / tb) .. " TiB"
  elseif bytes >= gb then
    return (bytes / gb) .. " GiB"
  elseif bytes >= mb then
    return (bytes / mb) .. " MiB"
  elseif bytes >= kb then
    return (bytes / kb) .. " KiB"
  end
  return bytes .. "B"
end

function printLBA(str, lba)
  print(str .. " = " .. lba .. " (offset = 0x" .. n2hex(lba*lba_size) .. ")")
end

function abort(msg)
  io.stderr:write(msg .. "\n")
  os.exit()
end

if #arg < 1 then
  abort("Usage: parsegpt.lua gptblock")
end

print(" Opening file " .. arg[1])
f = io.open(arg[1], "rb")
fsize = f:seek("end")
f:seek("set")
-- dd if=/dev/block/mmcblk0 bs=4096 count=6 of=/sdcard/gpt.bin
-- first usable LBA for partitions in
--   * 512-byte sector disk is 34 (off 0x4400) i.e, at 17 KiB (512B for Protective MBR + 512B for Primary GPT Header + 16KiB for Partition Entries)
--   * 4096-byte sector disk is 6 (off 0x6000) i.e, at 24 KiB (4KiB for Protective MBR + 4KiB for Primary GPT Header + 16KiB for Partition Entries)
-- So read 24 KiB for getting LBAs of all partition entries
if fsize > 24576 then
  dat = f:read(24576)
else
  dat = f:read("a")
end
f:close()

addr = find(GPT_SIGNATURE)
if not addr then
  abort("Signature not found")
end
lba_size = addr
if lba_size ~= 512 and lba_size ~= 4096 then
  abort("Unsupported sector size")
end

print("Sector Size : " .. lba_size)
print()

-- Skip LBA 0 (Logical Block Addressing) Protective MBR
-- LBA == Sector Size
seek(lba_size) -- Primary GPT is at offset of LBA 1



-- Read LBA 1 which is Primary GPT Header
-- Primary GPT Header is 92 bytes and 
-- rest of LBA is filled with null bytes
signature = getString(8) --off 0 (EFI PART)
print("Signature = " .. signature)

revision = read(4) --off 8 (00000100)
if revision ~= "\x00\x00\x01\x00" then
  abort("Revision = " .. b2hex(revision))
end
print("UEFI 2.8 Revision 00 00 01 00")

hdr_size = getInt() --off 12 (92)
print("Header Size = " .. hdr_size)
if hdr_size ~= 92 then
  abort("Unsupported GPT Header format")
end

hdrcrc = getInt() --off 16
print("CRC32 of Header = " .. hdrcrc)

seek(lba_size)
hdr1 = read(16)
read(4); hdr2 = "\x00\x00\x00\x00"
hdr3 = read(72)
hdrcrcCalc = crc32(hdr1 .. hdr2 .. hdr3)
if hdrcrcCalc ~= hdrcrc then
  abort("CRC32 of Header mismatched, got " .. hdrcrcCalc)
end

seek(lba_size + 20)
reserved = getInt() --off 20 (0)
print("Reserved = " .. reserved)
if reserved ~= 0 then
  abort("Unknown Reserved")
end

currentLBA = getLong() --off 24
printLBA("Current LBA", currentLBA)

backupLBA = getLong() --off 32
printLBA("Backup LBA", backupLBA)

firstusableLBA = getLong() --off 40
printLBA("First usable LBA for partitions", firstusableLBA)
if (lba_size == 4096 and firstusableLBA ~= 6) or (lba_size == 512 and firstusableLBA ~= 34) then
  print("   * Abnormal first usable LBA") -- Infinix Zero 8
end

lastusableLBA = getLong() --off 48
printLBA("Last usable LBA for partitions", lastusableLBA)

guid = read(16) --off 56
print("GUID = " .. getGUID(guid))

pentries_off = getLong() * lba_size --off 72 (2 * lba_size)
print("Partition Entries Offset = 0x" .. n2hex(pentries_off))
if pentries_off ~= 2*lba_size then
  abort("Abnormal Partition Entries Offset")
end

pentry_count = getInt() --off 80
print("Partition Count = " .. pentry_count)

pentry_size = getInt() --off 84 (128)
print("Partition Entry Size = " .. pentry_size)
if pentry_size ~= 128 then
  abort("Unsupported Partition Entry format")
end

parrcrc = getInt() --off 88
print("CRC32 of Partition Entries Array = " .. parrcrc)


seek(pentries_off)
peArray = read(pentry_count*pentry_size)
crcpeArray = crc32(peArray)
if crcpeArray ~= parrcrc then
  abort("CRC32 for Partition Entries Array mismatched, got " .. crcpeArray)
end

-- Header reading ended here (92 bytes)



seek(lba_size + 92)
reserved_count = pentries_off - getOff()
reserved = getString(reserved_count) -- 4004 nul bytes for 4096-byte sector disk and 420 for 512-byte sector
if reserved == "" then
  print("Reserved Null bytes : " .. reserved_count)
else
  print("Reserved bytes : " .. b2hex(reserved))
end



print()
print()

-- Seek to LBA 2
-- LBA 2 to LBA 5 (both including) incase of 4096-byte sector sized disk
-- LBA 2 to LBA 33 (both including) incase of 512-byte sector sized disk (16384 bytes, so 128 partitions can fit)
-- contains Partition Entries with each entry of 128 bytes
-- but partition count is given in Primary Header so no need to read all these LBAs
seek(pentries_off)
for i = 1, pentry_count do
  p_guid = read(16) --off 0
  p_unique_guid = read(16) --off 16
  p_firstLBA = getLong() --off 32
  p_lastLBA = getLong() --off 40
  flag1 = read(1) --off 48
  flag2 = read(1)
  flag3 = read(1)
  flag4 = read(1)
  flag5 = read(1)
  flag6 = read(1)
  flag7 = read(1)
  flag8 = read(1)
  p_name = getString(72) --off 56

  if p_guid ~= string.rep("\x00", 16) then
    print("No : " .. i)
    print("Partition Name = " .. p_name)

    p_size = (p_lastLBA - p_firstLBA) + 1
    io.write("Partition Size = " .. p_size .. " sectors " .. "(" .. get_unit(p_size*lba_size) .. ")")
    if i == pentry_count and p_lastLBA ~= lastusableLBA then
      io.write(" (may be not correct since last partition)")
    end
    print()

    print("Partition GUID = " .. getGUID(p_guid))
    print("Unique Partition GUID = " .. getGUID(p_unique_guid))
    printLBA("First LBA", p_firstLBA)
    printLBA("Last LBA", p_lastLBA)
    io.write("Attribute Flags = ")
    print(string.format("%s %s %s %s %s %s %s %s",
          b2hex(flag1), b2hex(flag2), b2hex(flag3), b2hex(flag4),
          b2hex(flag5), b2hex(flag6), b2hex(flag7), b2hex(flag8)))
--[[
-- flag8                     flag7                     flag6                     flag5                     flag4                     flag3                     flag2                     flag1
--63 62 61 60 59 58 57 56   55 54 53 52 51 50 49 48   47 46 45 44 43 42 41 40   39 38 37 36 35 34 33 32   31 30 29 28 27 26 25 24   23 22 21 20 19 18 17 16   15 14 13 12 11 10 9  8    7  6  5  4  3  2  1  0  big
-- 0  1  2  3  4  5  6  7    8  9 10 11 12 13 14 15   16 17 18 19 20 21 22 23   24 25 26 27 28 29 30 31   32 33 34 35 36 37 38 39   40 41 42 43 44 45 46 47   48 49 50 51 52 53 54 55   56 57 58 59 60 61 62 63 little

    ab_flags = splitbyte(flag7)
    print("Slot Active : " .. tostring(ab_flags[6]))
    print("Boot Successful : " .. tostring(ab_flags[2]))
    print("Unbootable : " .. tostring(ab_flags[1]))
]]
    print()
    if p_lastLBA == lastusableLBA and i ~= pentry_count then
      print(" wrong partition count. End of partiton entries reached at early")
      break
    end
  else
    print("Dummy partition at entry " .. i)
    print()
  end
end

print("Total Read Size : " .. get_unit(getOff()))

