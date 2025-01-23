import os
import win32api
import win32con
import hashlib
import time
from tkinter import Tk, filedialog
import pyperclip  # 用于复制文本到剪贴板
from colorama import Fore, init  # 导入 colorama 库

# 初始化 colorama
init(autoreset=True)

# 预设的特征码DFC和密码
EXPECTED_DFC = "3590669bbebb42003ecbeeb8a07928fce7a4c794548767abfd1cc776d4cf789f"
EXPECTED_PASSWORD = "441722mai"

# ========== 特征码处理部分 ==========

def get_mac_address():
    """获取设备的 MAC 地址"""
    mac = hex(uuid.getnode()).replace("0x", "").upper()
    mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    return mac


def get_disk_serial_number():
    """获取硬盘序列号 (仅限 Windows)"""
    try:
        output = subprocess.check_output("wmic diskdrive get serialnumber", shell=True)
        serial = output.decode().split("\n")[1].strip()
        return serial if serial else "UNKNOWN_DISK_SERIAL"
    except Exception as e:
        return f"ERROR: {e}"


def get_cpu_serial_number():
    """获取 CPU 序列号 (仅限 Windows)"""
    try:
        output = subprocess.check_output("wmic cpu get processorid", shell=True)
        serial = output.decode().split("\n")[1].strip()
        return serial if serial else "UNKNOWN_CPU_SERIAL"
    except Exception as e:
        return f"ERROR: {e}"


def get_device_uuid():
    """获取设备的 UUID (仅限 Windows)"""
    try:
        output = subprocess.check_output("wmic csproduct get uuid", shell=True)
        uuid_value = output.decode().split("\n")[1].strip()
        return uuid_value if uuid_value else "UNKNOWN_UUID"
    except Exception as e:
        return f"ERROR: {e}"


def compress_sequence_hash(sequence):
    """使用 SHA-256 哈希算法压缩序列码"""
    hash_object = hashlib.sha256(sequence.encode('utf-8'))
    return hash_object.hexdigest()


def generate_special_sequence():
    """生成特殊序列码，并使用哈希压缩"""
    mac = get_mac_address()
    disk_serial = get_disk_serial_number()
    cpu_serial = get_cpu_serial_number()
    device_uuid = get_device_uuid()

    # 按顺序拼接生成原始特殊序列码
    original_sequence = f"{mac}+{device_uuid}+{cpu_serial}+{disk_serial}"
    
    # 使用哈希算法压缩序列码
    compressed_sequence = compress_sequence_hash(original_sequence)

    return compressed_sequence

# ========== 文件管理部分 ==========

def remove_readonly_attribute(file_path):
    """移除文件的只读属性"""
    if os.path.exists(file_path):
        try:
            # 获取文件的属性
            win32api.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_NORMAL)
            print(f"已取消文件 {file_path} 的只读属性。")
        except Exception as e:
            print(f"取消只读属性时出现错误: {e}")
    else:
        print(f"文件 {file_path} 不存在!")

def add_file_label(file_path, label):
    """为文件添加标签，标签存储在文件的 Alternate Data Stream (ADS) 中"""
    if not os.path.exists(file_path):
        print(f"文件 {file_path} 不存在!")
        return

    try:
        # 先取消文件的只读属性
        remove_readonly_attribute(file_path)

        # 定义标签存储的 Alternate Data Stream
        ads_name = ":label"  # 可以更改为你想要的任何名称
        ads_path = file_path + ads_name

        # 将标签写入文件的 Alternate Data Stream
        with open(ads_path, "w", encoding="utf-8") as f:
            f.write(label)
        
        print(f"已为文件 {file_path} 添加标签：{label}")
    except PermissionError as e:
        print(f"权限错误: {e}")
    except Exception as e:
        print(f"出现错误: {e}")

def read_file_label(file_path):
    """读取文件的标签，标签存储在文件的 Alternate Data Stream (ADS) 中"""
    ads_name = ":label"
    ads_path = file_path + ads_name

    if os.path.exists(ads_path):
        try:
            # 从 Alternate Data Stream 读取标签
            with open(ads_path, "r", encoding="utf-8") as f:
                label = f.read()
            print(f"文件的标签是: {label}")
            return label
        except Exception as e:
            print(f"读取标签时出现错误: {e}")
            return None
    else:
        print(f"文件没有标签。")
        return None

def modify_file_bytes(file_path):
    """修改文件前 8 个字节"""
    with open(file_path, "rb") as file:
        data = file.read(8)
    
    # 确保读取到的字节数为 8
    if len(data) != 8:
        print(f"文件 {file_path} 长度不足 8 字节，跳过修改")
        return
    
    # 根据互换规则修改字节
    modified_data = bytearray(data)
    modified_data[0], modified_data[7] = modified_data[7], modified_data[0]  # 1-9
    modified_data[1], modified_data[6] = modified_data[6], modified_data[1]  # 2-8
    modified_data[2], modified_data[5] = modified_data[5], modified_data[2]  # 3-7
    modified_data[3], modified_data[4] = modified_data[4], modified_data[3]  # 4-6
    
    # 将修改后的数据写回文件
    with open(file_path, "r+b") as file:
        file.write(modified_data)

    print(f"文件 {file_path} 的前 8 个字节已成功修改")

def select_files():
    """让用户选择单个或多个文件"""
    root = Tk()  # 创建主窗口
    root.withdraw()  # 隐藏主窗口
    
    files = filedialog.askopenfilenames(title="选择文件")
    return files

# ========== 菜单界面和主程序入口 ==========

def show_menu():
    """显示菜单"""
    print(Fore.GREEN + "\n=== Made in XeroX ===")  # 使用绿色显示菜单标题
    print(Fore.CYAN + "当前时间:", time.strftime("%Y/%m/%d"))  # 使用青色显示当前时间
    print(Fore.YELLOW + "1. 加解密文件")  # 使用黄色显示菜单项
    print(Fore.YELLOW + "2. 查看特征码")  # 使用黄色显示菜单项
    print(Fore.YELLOW + "3. 查看文件状态")  # 新选项
    print("请选择功能 (1, 2, 或 3):", end=" ")

def handle_menu_choice(choice):
    """处理菜单选项"""
    if choice == "1":
        print("\n-- 加解密文件功能 --")
        files = select_files()
        if not files:
            print("未选择任何文件")
        else:
            for file in files:
                # 检查文件是否为只读状态
                if os.access(file, os.W_OK):
                    print("文件状态检测：通过")
                    modify_file_bytes(file)

                    # 检查文件标签
                    label = read_file_label(file)
                    if label == "已解密" or label is None:
                        add_file_label(file, "已加密")
                    elif label == "已加密":
                        add_file_label(file, "已解密")
                else:
                    print(Fore.RED + "文件状态检测：未通过（只读文件）")
                    print("无法修改只读文件，返回主菜单。")
                    break

    elif choice == "2":
        print("\n-- 当前设备特征码 --")
        device_feature_code = generate_special_sequence()
        print(f"当前设备特征码 DFC: {device_feature_code}")
        
        # 添加复制按钮（终端内模拟）
        print("\n按 [C] 复制 DFC 到剪贴板")
        user_input = input("请输入选项: ")
        if user_input.lower() == 'c':
            pyperclip.copy(device_feature_code)
            print("DFC 已复制到剪贴板!")
    
    elif choice == "3":
        print("\n-- 查看文件状态 --")
        files = select_files()
        if not files:
            print("未选择任何文件")
        else:
            for file in files:
                label = read_file_label(file)
                if label == "已加密":
                    print(f"{file} -> 文件已加密")
                else:
                    print(f"{file} -> 文件未加密")
    else:
        print("无效的选项")

def main():
    while True:
        # 显示菜单并获取选择
        show_menu()
        choice = input()

        # 处理选择
        handle_menu_choice(choice)

# 运行程序
if __name__ == "__main__":
    main()
