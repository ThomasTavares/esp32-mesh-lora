import os
Import("env")

nvs_bin_path = "nvs_key.bin"

def post_upload_nvs(source, target, env):
    upload_port = env.GetProjectOption("upload_port", env.subst("$UPLOAD_PORT"))
    
    python_exe = env.subst("$PYTHONEXE")
    
    platform = env.PioPlatform()
    esptool_dir = platform.get_package_dir("tool-esptoolpy")
    
    if not esptool_dir:
        print("\n[ERROR] PlatformIO could not locate the tool-esptoolpy package.")
        return
        
    esptool_path = os.path.join(esptool_dir, "esptool.py")
    
    print(f"\nFlashing NVS key to {upload_port}...")
    
    command = f'"{python_exe}" "{esptool_path}" --port {upload_port} write_flash 0x9000 "{nvs_bin_path}"'
    
    env.Execute(command)

# Attach this function to run immediately after the main firmware uploads
env.AddPostAction("upload", post_upload_nvs)