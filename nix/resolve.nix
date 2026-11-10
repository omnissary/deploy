# Read the declared deployment policy.
flake: if flake ? deploy then flake.deploy else throw "flake must declare deploy policy"
