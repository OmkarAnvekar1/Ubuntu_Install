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
    return f"ubuntu22-autoinstall-{timestamp}-{random_str}.iso"

# Generate the ISO filename
ISO_FILENAME = generate_iso_name()

# Remote working directories and files
REMOTE_WORKING_DIR = "/root/iso_mod_u22"
REMOTE_EXTRACT_DIR = f"{REMOTE_WORKING_DIR}/extract"
REMOTE_ISO_FILE = "/var/www/html/ubuntu-22.04.5.iso"  # Ubuntu 22.04 ISO
REMOTE_CRAFTED_ISO = f"/var/www/html/{ISO_FILENAME}"

# iDRAC Credentials and Configuration
IDRAC_IP = "10.219.106.200"
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

def modify_grub():
    """Modify GRUB configuration on Proxmox"""
    grub_file = f"{REMOTE_EXTRACT_DIR}/boot/grub/grub.cfg"
    
    print("Modifying GRUB configuration on Proxmox...")
    
    # Make a backup of the original file
    run_ssh_command(f"cp {grub_file} {grub_file}.backup")
    
    # Define the autoinstall menu entry for Ubuntu 22.04
    autoinstall_entry = """menuentry "Autoinstall Ubuntu Server" {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet autoinstall ds=nocloud-net\\;s=/cdrom/server/ apt-setup/disable-components=restricted,universe,multiverse apt-setup/no_mirror=true apt-setup/use_mirror=false apt.install.security=false security=false apt-setup/security_host= curtin/install_net_sources=false network-config/disable=true installers/curtin/offline=true offline=true debug=1 ---
    initrd  /casper/initrd
}
"""
    
    # Create a temporary file with the new content
    temp_script = f"""
    original_content=$(cat {grub_file})
    echo '{autoinstall_entry}' > {grub_file}
    echo "$original_content" >> {grub_file}
    """
    
    run_ssh_command(temp_script)
    print("GRUB configuration modified successfully")

def create_cloud_init():
    """Create cloud-init files on Proxmox"""
    server_dir = f"{REMOTE_EXTRACT_DIR}/server"
    
    print("Creating cloud-init files on Proxmox...")
    
    run_ssh_command(f"mkdir -p {server_dir}")
    
    # Create empty meta-data file
    run_ssh_command(f"touch {server_dir}/meta-data")
    
    # Create user-data file with the autoinstall configuration for Ubuntu 22.04
    user_data = """#cloud-config
autoinstall:
  version: 1
  interactive-sections: []
  locale: en_US.UTF-8
  keyboard: {layout: us}
  timezone: Etc/UTC
  identity:
    hostname: ubuntu-server
    username: ubuntu
    # Set to "ubuntu" for password
    password: "$6$exDY1mhS4KUYCE/2$zmn9ToZwTKLhCw.b4/b.ZRTIZM30JZ4QrOQ2aOXJ8yk96xpcCof0kxKwuX1kqLG/ygbJ1f8wxED22bTL4F46P0"
  storage:
    layout: {name: direct}
  network:
    version: 2
    renderer: networkd
    ethernets:
      eno3:
        dhcp4: false
        addresses: [10.219.94.148/25]
        gateway4: 10.219.94.129
        nameservers:
          addresses: [66.129.233.81]
  apt:
    disable_components: [restricted, universe, multiverse]
    geoip: false
    preserve_sources_list: false
    primary:
      - arches: [default]
        uri: file:///cdrom
    security:
      - arches: [default]
        uri: file:///cdrom
    unattended-upgrades:
      enabled: false
  package_update: false
  package_upgrade: false
  packages: [openssh-server]
  ssh:
    install-server: true
    allow-pw: true
  drivers:
    install: false
  kernel:
    package: linux-generic
  late-commands:
    - mkdir -p /target/etc/netplan
    - chmod 755 /target/etc/netplan
    - |
      cat > /target/etc/netplan/01-netcfg.yaml << EOF
      network:
        version: 2
        renderer: networkd
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
    - netplan apply --root=/target
"""
    
    # Write the user-data file
    user_data_cmd = f'''cat > {server_dir}/user-data << 'EOF'
{user_data}
EOF'''
    
    run_ssh_command(user_data_cmd)
    print("Cloud-init files created successfully")

def repack_iso():
    """Repack the ISO on Proxmox"""
    print("Repacking ISO on Proxmox...")
    
    # Check if we have BOOT directory extracted
    boot_check_cmd = f"if [ -d \"{REMOTE_WORKING_DIR}/BOOT\" ]; then echo 'BOOT_EXISTS'; else echo 'NO_BOOT'; fi"
    boot_exists = run_ssh_command(boot_check_cmd).strip()
    
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
        -c /boot.catalog \\
        -b /boot/grub/i386-pc/eltorito.img \\
        -no-emul-boot -boot-load-size 4 -boot-info-table --grub2-boot-info \\
        -eltorito-alt-boot \\
        -e --interval:appended_partition_2::: \\
        -no-emul-boot \\
        {REMOTE_EXTRACT_DIR}
        """
    else:
        # Simpler command
        xorriso_cmd = f"""
        xorriso -as mkisofs \\
        -o {REMOTE_CRAFTED_ISO} \\
        -J -r -V "UBUNTU_AUTOINSTALL" \\
        -b boot/grub/i386-pc/eltorito.img \\
        -no-emul-boot -boot-load-size 4 -boot-info-table \\
        -eltorito-alt-boot \\
        -e boot/grub/efi.img \\
        -no-emul-boot \\
        -isohybrid-gpt-basdat \\
        {REMOTE_EXTRACT_DIR}
        """
    
    try:
        run_ssh_command(xorriso_cmd)
        print(f"ISO successfully repacked on Proxmox to {REMOTE_CRAFTED_ISO}")
    except subprocess.CalledProcessError:
        print("Error with complex ISO repacking, trying fallback method...")
        
        # Fallback method
        fallback_cmd = f"""
        xorriso -as mkisofs \\
        -o {REMOTE_CRAFTED_ISO} \\
        -V "UBUNTU_AUTOINSTALL" \\
        -r -J \\
        -b boot/grub/i386-pc/eltorito.img \\
        -no-emul-boot \\
        -boot-load-size 4 \\
        -boot-info-table \\
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
        modify_grub()
        create_cloud_init()
        repack_iso()
        # Uncomment if you want to clean up temporary files
        # cleanup()
        print(f"✅ Autoinstall ISO creation completed successfully on Proxmox!")
        print(f"📀 The modified ISO is available at: {REMOTE_CRAFTED_ISO}")
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
    print("AUTOMATED UBUNTU 22.04 ISO CREATION AND IDRAC DEPLOYMENT")
    print("="*80)
    
    print(f"\n📀 Using randomly generated ISO filename: {ISO_FILENAME}")
    
    # Step 1: Create the custom ISO
    print("\n📀 STEP 1: Creating custom Ubuntu 22.04 ISO on Proxmox server...\n")
    if create_custom_iso():
        # Step 2: Mount the ISO via iDRAC and boot from it
        print("\n🔄 STEP 2: Mounting ISO on iDRAC and configuring boot...\n")
        time.sleep(5)  # Wait for ISO to be fully written
        if mount_iso_on_idrac():
            print("\n✅ SUCCESS: The Ubuntu 22.04 autoinstall process has been successfully initiated!")
            print(f"💻 The server at {IDRAC_IP} will now boot from the ISO and begin installation.")
            print("⏱️  Installation process typically takes 10-20 minutes to complete.")
        else:
            print("\n⚠️ WARNING: There was an issue with the iDRAC mounting process.")
            print(f"📀 The ISO is still available at: {ISO_URL}")
    else:
        print("\n❌ ERROR: Failed to create the custom Ubuntu 22.04 ISO.")
        print("Please check the logs above for more details.")

if __name__ == "__main__":
    main()
