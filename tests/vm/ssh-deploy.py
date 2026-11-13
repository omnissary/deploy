start_all()
controller.wait_for_unit("multi-user.target")
target.wait_for_unit("sshd")

with subtest("provision credentials through the packaged CLI"):
    controller.succeed("prepare-deploy-test")
    authorize_controller(target)
    run_deploy("machine", "provision", "target")
    run_deploy("host", "set", "target", "target")
    controller.succeed(
        "cd /root/repo && find vars -type f -print0 | sort -z | xargs -0 sha256sum > /root/before-provision"
    )
    run_deploy("machine", "provision", "target")
    controller.succeed("cd /root/repo && sha256sum --check /root/before-provision")

with subtest("arrange the managed bootstrap host identity"):
    controller.succeed(
        "sops --decrypt --input-type binary --output-type binary /root/repo/vars/secrets/target/openssh/ssh_host_ed25519_key | ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/root/bootstrap-hosts root@target 'umask 077; cat > /etc/ssh/ssh_host_ed25519_key'"
    )
    target.succeed("systemctl restart sshd")
    target.wait_for_unit("sshd")
    # The running daemon retains its key; deployment must repair the missing file.
    target.succeed("rm /etc/ssh/ssh_host_ed25519_key")

with subtest("copy a real system closure and activate it over SSH"):
    output = run_deploy("machine", "deploy", "target")
    assert (
        "deploy: starting deployment" not in output
    ), "info log appeared without --verbose"
    target.wait_for_unit("sshd")
    assert target.succeed("cat /etc/deploy-test-generation").strip() == "updated"
    remote_public = target.succeed(
        "ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key"
    ).split()[:2]
    local_public = controller.succeed(
        "cat /root/repo/vars/secrets/target/openssh/ssh_host_ed25519_key.pub"
    ).split()[:2]
    assert (
        remote_public == local_public
    ), "deployed host key differs from provisioned identity"
    controller.fail("test -e /root/repo/vars/secrets/target/initrd-ssh/id_ed25519")

with subtest("repeat deployment preserves identity and encrypted material"):
    output = run_deploy("--verbose", "machine", "deploy", "target")
    assert (
        "deploy: remote ssh host key already matches" in output
    ), "repeat deploy did not recognize the managed host key"
    assert "INF" not in output, "structured log level leaked into CLI output"
    controller.succeed("cd /root/repo && sha256sum --check /root/before-provision")
    assert target.succeed("cat /etc/deploy-test-generation").strip() == "updated"

with subtest("failed transport cannot activate or generate credentials"):
    target.succeed("systemctl stop sshd")
    expect_deploy_failure("SSH transport failure", "ssh", "machine", "deploy", "target")
    controller.succeed("cd /root/repo && sha256sum --check /root/before-provision")
    assert target.succeed("cat /etc/deploy-test-generation").strip() == "updated"
