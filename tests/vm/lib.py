import shlex


def deploy_command(*args):
    return "deploy --flake /root/repo " + shlex.join(args) + " < /dev/null 2>&1"


def run_deploy(*args):
    return controller.succeed(deploy_command(*args), timeout=240)


def expect_deploy_failure(label, diagnostic, *args):
    status, output = controller.execute(deploy_command(*args), timeout=90)
    assert status != 0, f"{label}: command unexpectedly succeeded"
    assert diagnostic in output, f"{label}: missing {diagnostic!r} in {output}"


def authorize_controller(machine):
    public_key = controller.succeed("cat /root/.ssh/id_ed25519.pub").strip()
    machine.succeed(
        "mkdir -p -m 700 /root/.ssh && printf '%s\\n' "
        + shlex.quote(public_key)
        + " >> /root/.ssh/authorized_keys"
    )
