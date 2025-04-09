import subprocess
import os
import requests
import json
import time
import sys
import logging
import random
import string

# Proxmox server details
PROXMOX_IP = "10.219.82.112"
PROXMOX_USER = "root"
PROXMOX_PASSWORD = "Jtaclab123"

# Generate a random ISO filename
def generate_iso_name():
    """Generate a random name for the ISO file"""
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"ubuntu20-autoinstall-{timestamp}-{random_str}.iso"

# Generate the ISO filename
ISO_FILENAME = generate_iso_name()

# Remote working directories and files
REMOTE_WORKING_DIR = "/root/iso_mod_u20"  # Changed working directory for Ubuntu 20
REMOTE_EXTRACT_DIR = f"{REMOTE_WORKING_DIR}/extract"
REMOTE_ISO_FILE = "/var/www/html/ubuntu-20.04.6-live-server.iso"  # Ubuntu 20.04 ISO
REMOTE_CRAFTED_ISO = f"/var/www/html/{ISO_FILENAME}"

# iDRAC Credentials and Configuration
IDRAC_IP = "10.219.106.203"
IDRAC_USER = "root"
IDRAC_PASS = "Jtaclab123"
ISO_URL = f"http://{PROXMOX_IP}/{ISO_FILENAME}"

# Redfish API Endpoints
SESSION_URL = f"https://{IDRAC_IP}/redfish/v1/SessionService/Sessions"
VM_INSERT_URL = f"https://{IDRAC_IP}/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/CD/Actions/VirtualMedia.InsertMedia"
VM_STATUS_URL = f"https://{IDRAC_IP}/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/CD"
BOOT_ORDER_URL = f"https://{IDRAC_IP}/redfish/v1/Systems/System.Embedded.1"
RESET_URL = f"https://{IDRAC_IP}/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset"
ATTRIBUTES_URL = f"https://{IDRAC_IP}/redfish/v1/Managers/iDRAC.Embedded.1/Attributes/"

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

def run_ssh_command(command):
    """Run a command on the remote Proxmox server using sshpass"""
    ssh_command = [
        "sshpass", 
        "-p", 
        PROXMOX_PASSWORD,
        "ssh", 
        "-o", "StrictHostKeyChecking=no",
        f"{PROXMOX_USER}@{PROXMOX_IP}",
        command
    ]
    result = subprocess.run(ssh_command, check=True, capture_output=True, text=True)
    return result.stdout

def ensure_sshpass_installed():
    """Make sure sshpass is installed on the local machine"""
    try:
        subprocess.run(["which", "sshpass"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("sshpass not found. Installing sshpass...")
        try:
            # Try to detect the OS and install sshpass
            if os.path.exists("/usr/bin/apt"):
                subprocess.run(["sudo", "apt-get", "install", "-y", "sshpass"], check=True)
            elif os.path.exists("/usr/bin/yum"):
                subprocess.run(["sudo", "yum", "install", "-y", "sshpass"], check=True)
            elif os.path.exists("/usr/bin/brew"):
                subprocess.run(["brew", "install", "sshpass"], check=True)
            else:
                print("Could not automatically install sshpass. Please install it manually.")
                exit(1)
        except subprocess.CalledProcessError:
            print("Failed to install sshpass. Please install it manually.")
            exit(1)

def setup_remote_environment():
    """Set up the working directory on the Proxmox server"""
    print("Setting up remote working environment...")
    run_ssh_command(f"mkdir -p {REMOTE_WORKING_DIR} {REMOTE_EXTRACT_DIR}")
    
    # Make sure /var/www/html exists and has proper permissions
    run_ssh_command("mkdir -p /var/www/html && chmod 755 /var/www/html")
    
    # Install necessary tools on Proxmox (Debian-based)
    run_ssh_command("apt-get update && apt-get install -y p7zip-full wget xorriso")

def extract_iso():
    """Extract the ISO on the Proxmox server"""
    print("Extracting ISO on Proxmox server...")
    
    # Clear extract directory if it exists
    run_ssh_command(f"rm -rf {REMOTE_EXTRACT_DIR}/* && mkdir -p {REMOTE_EXTRACT_DIR}")
    
    # Extract using 7z
    run_ssh_command(f"7z x {REMOTE_ISO_FILE} -o{REMOTE_EXTRACT_DIR}")
    
    # Ensure we have write permissions
    run_ssh_command(f"chmod -R u+w {REMOTE_EXTRACT_DIR}")
    
    # Handle [BOOT] folder if it exists
    run_ssh_command(f"""
        if [ -d "{REMOTE_EXTRACT_DIR}/[BOOT]" ]; then
            BOOT_DEST="{REMOTE_WORKING_DIR}/BOOT"
            rm -rf "$BOOT_DEST" 2>/dev/null
            mv "{REMOTE_EXTRACT_DIR}/[BOOT]" "$BOOT_DEST"
        fi
    """)
    
    print("ISO content extracted successfully on Proxmox")

def modify_grub_and_txt_cfg():
    """Modify GRUB and isolinux configurations on Proxmox for Ubuntu 20.04"""
    print("Modifying boot configurations on Proxmox...")
    
    # Modify GRUB configuration
    grub_file = f"{REMOTE_EXTRACT_DIR}/boot/grub/grub.cfg"
    
    # Make a backup of the original file
    run_ssh_command(f"cp {grub_file} {grub_file}.backup")
    
    # Define the autoinstall menu entry for Ubuntu 20.04
    autoinstall_entry = """menuentry "Autoinstall Ubuntu Server" {
    set gfxpayload=keep
    linux /casper/vmlinuz quiet autoinstall ds=nocloud-net\\;s=/cdrom/server/ ip=10.219.94.148::10.219.94.129:255.255.255.128:ubuntu-server:eno3:off nameserver=66.129.233.81 apt-setup/disable-components=restricted,universe,multiverse apt-setup/no_mirror=true apt-setup/use_mirror=false apt.install.security=false security=false apt-setup/security_host= curtin/install_net_sources=false network-config/disable=true installers/curtin/offline=true offline=true fsck.mode=skip debug=1 ---
    initrd /casper/initrd
}
"""
    
    # Create a temporary file with the new content for GRUB
    grub_script = f"""
    original_content=$(cat {grub_file})
    echo '{autoinstall_entry}' > {grub_file}
    echo "$original_content" >> {grub_file}
    """
    
    run_ssh_command(grub_script)
    
    # Modify isolinux configuration (txt.cfg)
    txt_cfg_file = f"{REMOTE_EXTRACT_DIR}/isolinux/txt.cfg"
    
    # Check if the txt.cfg file exists
    txt_file_exists = run_ssh_command(f"test -f {txt_cfg_file} && echo 'exists' || echo 'not found'").strip()
    
    if txt_file_exists == 'exists':
        # Make a backup of the original file
        run_ssh_command(f"cp {txt_cfg_file} {txt_cfg_file}.backup")
        
        # Define the autoinstall menu entry for isolinux
        isolinux_entry = """label autoinstall
  menu label ^Autoinstall Ubuntu Server
  kernel /casper/vmlinuz
  append file=/cdrom/preseed/ubuntu-server.seed quiet autoinstall ds=nocloud;s=/cdrom/nocloud/ ip=10.219.94.148::10.219.94.129:255.255.255.128:ubuntu-server:eno3:off nameserver=66.129.233.81 apt-setup/disable-components=restricted,universe,multiverse apt-setup/no_mirror=true apt-setup/use_mirror=false apt.install.security=false security=false apt-setup/security_host= curtin/install_net_sources=false network-config/disable=true installers/curtin/offline=true offline=true fsck.mode=skip initrd=/casper/initrd ---
"""
        
        # Script to insert the entry and make it default
        txt_script = f"""
        # Add our entry at the top or before "label install"
        if grep -q "label install" {txt_cfg_file}; then
            sed -i 's/label install/{isolinux_entry}label install/' {txt_cfg_file}
        else
            original_content=$(cat {txt_cfg_file})
            echo '{isolinux_entry}' > {txt_cfg_file}
            echo "$original_content" >> {txt_cfg_file}
        fi
        # Make our entry the default
        if grep -q "default install" {txt_cfg_file}; then
            sed -i 's/default install/default autoinstall/' {txt_cfg_file}
        fi
        """
        
        run_ssh_command(txt_script)
        
        # Make sure isolinux.cfg also has our entry as default
        isolinux_cfg_file = f"{REMOTE_EXTRACT_DIR}/isolinux/isolinux.cfg"
        isolinux_exists = run_ssh_command(f"test -f {isolinux_cfg_file} && echo 'exists' || echo 'not found'").strip()
        
        if isolinux_exists == 'exists':
            isolinux_script = f"""
            # Make autoinstall the default
            if grep -q "default vesamenu.c32" {isolinux_cfg_file}; then
                sed -i 's/default vesamenu.c32/default autoinstall/' {isolinux_cfg_file}
            fi
            """
            run_ssh_command(isolinux_script)
    
    print("Boot configurations modified successfully on Proxmox")

def create_cloud_init():
    """Create all necessary cloud-init files on Proxmox for Ubuntu 20.04"""
    print("Creating cloud-init files on Proxmox...")
    
    # Create directories for cloud-init files
    run_ssh_command(f"""
    mkdir -p {REMOTE_EXTRACT_DIR}/nocloud
    mkdir -p {REMOTE_EXTRACT_DIR}/casper/nocloud
    mkdir -p {REMOTE_EXTRACT_DIR}/server
    mkdir -p {REMOTE_EXTRACT_DIR}/preseed
    """)
    
    # Create meta-data file
    meta_data_content = """instance-id: ubuntu-20-server
local-hostname: ubuntu-server
"""
    
    meta_data_cmd = f"""cat > {REMOTE_EXTRACT_DIR}/nocloud/meta-data << 'EOF'
{meta_data_content}
EOF
# Copy to other locations
cp {REMOTE_EXTRACT_DIR}/nocloud/meta-data {REMOTE_EXTRACT_DIR}/casper/nocloud/meta-data
cp {REMOTE_EXTRACT_DIR}/nocloud/meta-data {REMOTE_EXTRACT_DIR}/server/meta-data
"""
    
    run_ssh_command(meta_data_cmd)
    
    # Create user-data file with autoinstall config
    user_data = """#cloud-config
autoinstall:
  version: 1
  early-commands:
    # Ensure autoinstall is recognized
    - mkdir -p /run/auto-install-started
    - touch /run/auto-install-started/started
    # Force the installer to work in offline mode
    - echo "APT::Get::AllowUnauthenticated \"true\";" > /etc/apt/apt.conf.d/99-offline
  refresh-installer:
    update: no
  locale: en_US.UTF-8
  keyboard: {layout: us}
  identity:
    hostname: ubuntu-server
    username: ubuntu
    # Password: ubuntu
    password: "$6$exDY1mhS4KUYCE/2$zmn9ToZwTKLhCw.b4/b.ZRTIZM30JZ4QrOQ2aOXJ8yk96xpcCof0kxKwuX1kqLG/ygbJ1f8wxED22bTL4F46P0"
  network:
    version: 2
    ethernets:
      eno3:
        dhcp4: no
        addresses: [10.219.94.148/25]
        gateway4: 10.219.94.129
        nameservers:
          addresses: [66.129.233.81]
  apt:
    preserve_sources_list: false
    cdrom: true
    disable_components: []
    primary: []
    # Disable all online repositories
    disable_suites: [security, updates, backports]
    # Only install what's strictly needed from the CD
  packages:
    - openssh-server
  user-data:
    disable_root: false
  timezone: UTC
  storage:
    layout:
      name: direct
  late-commands:
    # Disable apt sources that might try to reach online repositories
    - echo "# No online repositories" > /target/etc/apt/sources.list
    - echo "# CD-ROM sources only" > /target/etc/apt/sources.list.d/cdrom.list
    - mkdir -p /target/etc/netplan
    - chmod 755 /target/etc/netplan
    - |
      cat > /target/etc/netplan/01-netcfg.yaml << EOF
      network:
        version: 2
        ethernets:
          eno3:
            dhcp4: no
            addresses:
              - 10.219.94.148/25
            routes:
              - to: default
                via: 10.219.94.129
            nameservers:
              addresses: [66.129.233.81]
      EOF
    - chmod 644 /target/etc/netplan/01-netcfg.yaml
    - |
      echo "network: {config: disabled}" > /target/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
    - |
      echo "APT::Get::AllowUnauthenticated \"true\";" > /target/etc/apt/apt.conf.d/99-offline
    - |
      echo "Acquire::AllowInsecureRepositories \"true\";" >> /target/etc/apt/apt.conf.d/99-offline
    - |
      echo "Acquire::AllowDowngradeToInsecureRepositories \"true\";" >> /target/etc/apt/apt.conf.d/99-offline
"""
    
    user_data_cmd = f"""cat > {REMOTE_EXTRACT_DIR}/nocloud/user-data << 'EOF'
{user_data}
EOF
# Copy to other locations
cp {REMOTE_EXTRACT_DIR}/nocloud/user-data {REMOTE_EXTRACT_DIR}/casper/nocloud/user-data
cp {REMOTE_EXTRACT_DIR}/nocloud/user-data {REMOTE_EXTRACT_DIR}/server/user-data
"""
    
    run_ssh_command(user_data_cmd)
    
    # Create empty vendor-data files
    vendor_data_cmd = f"""
    echo "#cloud-config" > {REMOTE_EXTRACT_DIR}/nocloud/vendor-data
    echo "{{}}" >> {REMOTE_EXTRACT_DIR}/nocloud/vendor-data
    cp {REMOTE_EXTRACT_DIR}/nocloud/vendor-data {REMOTE_EXTRACT_DIR}/casper/nocloud/vendor-data
    cp {REMOTE_EXTRACT_DIR}/nocloud/vendor-data {REMOTE_EXTRACT_DIR}/server/vendor-data
    """
    
    run_ssh_command(vendor_data_cmd)
    
    # Create preseed file
    preseed_content = """# Basic preseed file that triggers autoinstall
d-i auto-install/enable boolean true
d-i preseed/early_command string anna-install file-preseed
d-i file-preseed/url string file:///cdrom/nocloud/user-data
d-i apt-setup/disable-components string restricted,universe,multiverse
d-i apt-setup/no_mirror boolean true
d-i apt-setup/use_mirror boolean false
d-i apt-setup/security_host string
d-i apt-setup/services-select multiselect none
d-i pkgsel/update-policy select none
"""
    
    preseed_cmd = f"""cat > {REMOTE_EXTRACT_DIR}/preseed/ubuntu-server.seed << 'EOF'
{preseed_content}
EOF
"""
    
    run_ssh_command(preseed_cmd)
    
    print("Cloud-init and preseed files created successfully on Proxmox")

def repack_iso():
    """Repack the ISO on Proxmox"""
    print("Repacking ISO on Proxmox...")
    
    # Check if isolinux.bin exists and get its path
    isolinux_check = f"find {REMOTE_EXTRACT_DIR} -name 'isolinux.bin' | head -1"
    isolinux_path = run_ssh_command(isolinux_check).strip()
    
    if isolinux_path:
        isolinux_bin = os.path.relpath(isolinux_path, REMOTE_EXTRACT_DIR)
        isolinux_dir = os.path.dirname(isolinux_bin)
        boot_catalog = f"{isolinux_dir}/boot.cat"
        print(f"Found isolinux.bin at: {isolinux_bin}")
        print(f"Using boot catalog at: {boot_catalog}")
        
        # Check if we have BOOT directory extracted
        boot_check_cmd = f"if [ -d \"{REMOTE_WORKING_DIR}/BOOT\" ]; then echo 'BOOT_EXISTS'; else echo 'NO_BOOT'; fi"
        boot_exists = run_ssh_command(boot_check_cmd).strip()
        
        # Look for EFI boot image
        efi_img_check = f"find {REMOTE_EXTRACT_DIR} -name 'efi.img' | head -1"
        efi_img_path = run_ssh_command(efi_img_check).strip()
        efi_path = ""
        if efi_img_path:
            efi_path = os.path.relpath(efi_img_path, REMOTE_EXTRACT_DIR)
            print(f"Found EFI boot image at: {efi_path}")
        
        if boot_exists == 'BOOT_EXISTS':
            # Complex command with BOOT files
            xorriso_cmd = f"""
            xorriso -as mkisofs -r \\
            -V "UBUNTU_AUTOINSTALL" \\
            -o {REMOTE_CRAFTED_ISO} \\
            --grub2-mbr {REMOTE_WORKING_DIR}/BOOT/1-Boot-NoEmul.img \\
            -partition_offset 16 \\
            --mbr-force-bootable \\
            -append_partition 2 28732ac11ff8d211ba4b00a0c93ec93b \\
            {REMOTE_WORKING_DIR}/BOOT/2-Boot-NoEmul.img \\
            -appended_part_as_gpt \\
            -iso_mbr_part_type a2a0d0ebe5b9334487c068b6b72699c7 \\
            -c /{boot_catalog} \\
            -b /{isolinux_bin} \\
            -no-emul-boot -boot-load-size 4 -boot-info-table \\
            {REMOTE_EXTRACT_DIR}
            """
        elif efi_path:
            # Regular bootable ISO with EFI support
            xorriso_cmd = f"""
            xorriso -as mkisofs \\
            -o {REMOTE_CRAFTED_ISO} \\
            -J -r -V "UBUNTU_AUTOINSTALL" \\
            -joliet-long \\
            -c /{boot_catalog} \\
            -b /{isolinux_bin} \\
            -no-emul-boot -boot-load-size 4 -boot-info-table \\
            -eltorito-alt-boot \\
            -e /{efi_path} \\
            -no-emul-boot \\
            -isohybrid-gpt-basdat \\
            {REMOTE_EXTRACT_DIR}
            """
        else:
            # Basic bootable ISO
            xorriso_cmd = f"""
            xorriso -as mkisofs \\
            -o {REMOTE_CRAFTED_ISO} \\
            -J -r -V "UBUNTU_AUTOINSTALL" \\
            -joliet-long \\
            -c /{boot_catalog} \\
            -b /{isolinux_bin} \\
            -no-emul-boot -boot-load-size 4 -boot-info-table \\
            {REMOTE_EXTRACT_DIR}
            """
    else:
        # Fallback method if isolinux.bin not found
        xorriso_cmd = f"""
        xorriso -as mkisofs \\
        -o {REMOTE_CRAFTED_ISO} \\
        -V "UBUNTU_AUTOINSTALL" \\
        -r -J \\
        {REMOTE_EXTRACT_DIR}
        """
    
    try:
        print("Running xorriso command...")
        run_ssh_command(xorriso_cmd)
        print(f"ISO successfully repacked on Proxmox to {REMOTE_CRAFTED_ISO}")
    except subprocess.CalledProcessError:
        print("Error with ISO repacking, trying fallback method...")
        # Fallback method
        fallback_cmd = f"""
        xorriso -as mkisofs \\
        -o {REMOTE_CRAFTED_ISO} \\
        -V "UBUNTU_AUTOINSTALL" \\
        -r -J \\
        {REMOTE_EXTRACT_DIR}
        """
        run_ssh_command(fallback_cmd)
        print(f"ISO successfully repacked using fallback method on Proxmox to {REMOTE_CRAFTED_ISO}")

def cleanup():
    """Optional cleanup of temporary files"""
    print("Cleaning up temporary files...")
    run_ssh_command(f"rm -rf {REMOTE_EXTRACT_DIR}")
    run_ssh_command(f"rm -rf {REMOTE_WORKING_DIR}/BOOT 2>/dev/null || true")
    print("Cleanup completed")

def create_session():
    """Create an iDRAC session and return headers with authentication token"""
    headers = {'Content-Type': 'application/json'}
    payload = {"UserName": IDRAC_USER, "Password": IDRAC_PASS}
    
    # Disable SSL warnings for self-signed certificates
    requests.packages.urllib3.disable_warnings()
    
    session = requests.post(SESSION_URL, json=payload, headers=headers, verify=False)

    if session.status_code != 201:
        logging.error(f"❌ Authentication Failed: {session.text}")
        return None, None

    token = session.headers['X-Auth-Token']
    session_uri = session.headers['Location']
    if session_uri.startswith("/"):
        session_uri = f"https://{IDRAC_IP}{session_uri}"

    headers['X-Auth-Token'] = token
    logging.info("✅ Authenticated Successfully.")
    return headers, session_uri

def close_session(headers, session_uri):
    """Close the iDRAC session"""
    close_response = requests.delete(session_uri, headers=headers, verify=False)
    if close_response.status_code in [200, 204]:
        logging.info("🔒 Closed iDRAC session.")
    else:
        logging.warning(f"⚠️ Failed to close session: {close_response.text}")

def check_iso_status(headers):
    """Check if ISO is already mounted"""
    response = requests.get(VM_STATUS_URL, headers=headers, verify=False)
    if response.status_code == 200:
        vm_info = response.json()
        current_image = vm_info.get('Image', None)
        if current_image == ISO_URL:
            logging.info("✅ ISO is already mounted.")
            return True
        elif current_image:
            logging.warning(f"⚠️ Another ISO is mounted: {current_image}")
        else:
            logging.info("ℹ️ No ISO currently mounted.")
    else:
        logging.error(f"❌ Failed to check Virtual Media status: {response.text}")
    return False

def mount_iso(headers):
    """Mount the ISO via iDRAC"""
    iso_payload = {
        "Image": ISO_URL,
        "Inserted": True,
        "WriteProtected": True
    }
    response = requests.post(VM_INSERT_URL, json=iso_payload, headers=headers, verify=False)

    if response.status_code in [200, 204]:
        logging.info("✅ ISO Mounted Successfully.")
        return True
    else:
        logging.error(f"❌ Failed to Mount ISO: {response.text}")
        return False

def set_boot_device(headers):
    """Set first boot device to Virtual CD/DVD"""
    boot_payload = {
        "Attributes": {
            "ServerBoot.1.FirstBootDevice": "VCD-DVD"
        }
    }
    
    response = requests.patch(ATTRIBUTES_URL, json=boot_payload, headers=headers, verify=False)
    
    if response.status_code in [200, 204]:
        logging.info("✅ First Boot Device set to Virtual CD/DVD.")
        return True
    else:
        logging.error(f"❌ Failed to set first boot device: {response.text}")
        return False

def enable_boot_once(headers):
    """Enable one-time boot for Virtual Media"""
    boot_once_payload = {
        "Attributes": {
            "VirtualMedia.1.BootOnce": "Enabled"
        }
    }
    
    response = requests.patch(ATTRIBUTES_URL, json=boot_once_payload, headers=headers, verify=False)
    
    if response.status_code in [200, 204]:
        logging.info("✅ One-Time Boot enabled for Virtual Media.")
        return True
    else:
        logging.error(f"❌ Failed to enable one-time boot: {response.text}")
        return False

def reboot_server(headers):
    """Reboot the server to boot from Virtual CD/DVD"""
    reboot_payload = {"ResetType": "ForceRestart"}
    response = requests.post(RESET_URL, json=reboot_payload, headers=headers, verify=False)

    if response.status_code in [200, 204]:
        logging.info("🔄 Server reboot initiated successfully.")
        return True
    else:
        logging.error(f"❌ Failed to reboot server: {response.text}")
        return False

def create_custom_iso():
    """Create a custom Ubuntu ISO with automated installation"""
    try:
        ensure_sshpass_installed()
        setup_remote_environment()
        extract_iso()
        modify_grub_and_txt_cfg()
        create_cloud_init()
        repack_iso()
        # Uncomment if you want to clean up temporary files
        # cleanup()
        print(f"✅ Autoinstall ISO creation completed successfully on Proxmox!")
        print(f"📀 The modified Ubuntu 20.04 ISO is available at: {REMOTE_CRAFTED_ISO}")
        return True
    except Exception as e:
        print(f"❌ Error during ISO creation: {e}")
        import traceback
        traceback.print_exc()
        return False

def mount_iso_on_idrac():
    """Mount the ISO on iDRAC and set boot options"""
    # Disable SSL warnings for self-signed certificates
    requests.packages.urllib3.disable_warnings()
    
    headers, session_uri = create_session()
    if not headers:
        return False
    
    success = True
    
    try:
        # Step 1: Check if ISO is already mounted
        if not check_iso_status(headers):
            # Step 2: Mount ISO
            if mount_iso(headers):
                time.sleep(5)  # Wait for ISO to be recognized
            else:
                success = False
        
        # Step 3: Set boot device to Virtual CD/DVD
        if not set_boot_device(headers):
            success = False
        
        # Step 4: Enable one-time boot
        if not enable_boot_once(headers):
            success = False
            
        # Step 5: Reboot the server if all previous steps were successful
        if success:
            logging.info("- INFO: System will now reboot and boot from Virtual CD.")
            if not reboot_server(headers):
                success = False
        else:
            logging.info("- INFO: One or more steps failed. Server reboot skipped.")
    
    finally:
        # Always close the session
        close_session(headers, session_uri)
    
    return success

def main():
    """Main function to run the entire process"""
    print("="*80)
    print("AUTOMATED UBUNTU 20.04 ISO CREATION AND IDRAC DEPLOYMENT")
    print("="*80)
    
    print(f"\n📀 Using randomly generated ISO filename: {ISO_FILENAME}")
    
    # Step 1: Create the custom ISO
    print("\n📀 STEP 1: Creating custom Ubuntu 20.04 ISO on Proxmox server...\n")
    if create_custom_iso():
        # Step 2: Mount the ISO via iDRAC and boot from it
        print("\n🔄 STEP 2: Mounting ISO on iDRAC and configuring boot...\n")
        time.sleep(5)  # Wait for ISO to be fully written
        if mount_iso_on_idrac():
            print("\n✅ SUCCESS: The Ubuntu 20.04 autoinstall process has been successfully initiated!")
            print(f"💻 The server at {IDRAC_IP} will now boot from the ISO and begin installation.")
            print("⏱️  Installation process typically takes 10-20 minutes to complete.")
        else:
            print("\n⚠️ WARNING: There was an issue with the iDRAC mounting process.")
            print(f"📀 The ISO is still available at: {ISO_URL}")
    else:
        print("\n❌ ERROR: Failed to create the custom Ubuntu 20.04 ISO.")
        print("Please check the logs above for more details.")

if __name__ == "__main__":
    main()
