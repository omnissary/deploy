import argparse


def run_zfs_install(argv):
    parser = argparse.ArgumentParser(
        description="Test installation and cold-boot unlock of encrypted ZFS"
    )
    parser.add_argument("--key-path", required=True)
    parser.add_argument("--initrd-key-path", required=True)
    args = parser.parse_args(argv)

    def wait_for_initrd_ssh():
        controller.wait_until_succeeds(
            "ssh-keyscan -T 2 -p 2222 -t ed25519 target > /root/initrd-host-key 2>/dev/null",
            timeout=180,
        )
        controller.fail("timeout 2 bash -c 'exec 3<>/dev/tcp/target/22'")
        expected_key = controller.succeed(
            "cat /root/repo/vars/secrets/target/initrd-ssh/id_ed25519.pub"
        ).split()[:2]
        keyscan_output = controller.succeed("cat /root/initrd-host-key")
        offered_keys = [
            line.split()[1:3]
            for line in keyscan_output.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        assert offered_keys and all(
            key == expected_key for key in offered_keys
        ), f"initrd SSH identity: expected {expected_key!r}, got {offered_keys!r}"

    controller.start()
    installer.start()
    controller.wait_for_unit("multi-user.target")
    installer.wait_for_unit("sshd")

    with subtest("provision an encrypted root without rotating its key"):
        controller.succeed("prepare-deploy-test")
        run_deploy("machine", "provision", "target")
        controller.succeed(
            "deploy --flake /root/repo secret get target rpool-root-key | sha256sum > /root/pool-key-before"
        )
        run_deploy("machine", "provision", "target")
        controller.succeed(
            "deploy --flake /root/repo secret get target rpool-root-key | sha256sum --check /root/pool-key-before"
        )

    with subtest("install through real nixos-anywhere and Disko"):
        controller.succeed(
            deploy_command(
                "machine", "init", "--phases", "disko,install", "target", "installer"
            ),
            timeout=900,
        )
        installer.succeed(
            f"test -s /mnt/etc/ssh/ssh_host_ed25519_key && test -s /mnt{shlex.quote(args.initrd_key_path)}"
        )
        installer.fail(f"test -e /mnt{shlex.quote(args.key_path)}")
        assert (
            installer.succeed("zfs get -H -o value encryption rpool").strip()
            == "aes-256-gcm"
        )
        installer.succeed("umount -R /mnt && zpool export rpool")
        installer.shutdown()
        run_deploy("host", "set", "target", "target")
        run_deploy("host", "set", "--tag", "unlock", "target", "target")

    with subtest("boot blocks in initrd until deploy delivers the stored key"):
        target.start()
        target.wait_for_console_text(
            "deploy test: waiting for encrypted root key", timeout=180
        )
        wait_for_initrd_ssh()
        run_deploy("machine", "unlock", "target")
        target.wait_for_unit("multi-user.target", timeout=180)
        assert target.succeed("findmnt -n -o FSTYPE /").strip() == "zfs"
        assert (
            target.succeed("cat /etc/deploy-test-installed").strip()
            == "encrypted ZFS root"
        )
        assert (
            target.succeed("zfs get -H -o value keystatus rpool").strip() == "available"
        )
        controller.succeed(
            "deploy --flake /root/repo secret get target rpool-root-key | sha256sum --check /root/pool-key-before"
        )

    with subtest("a second cold boot still requires the same stored key"):
        target.shutdown()
        target.start()
        wait_for_initrd_ssh()
        run_deploy("machine", "unlock", "target")
        target.wait_for_unit("multi-user.target", timeout=180)
        assert target.succeed("findmnt -n -o FSTYPE /").strip() == "zfs"
        controller.succeed(
            "deploy --flake /root/repo secret get target rpool-root-key | sha256sum --check /root/pool-key-before"
        )
