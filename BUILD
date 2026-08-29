load("@rules_python//python:defs.bzl", "py_binary")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

exports_files([
    "adversarial_banner.png",
    "adversarial_invoice.pdf",
    "adversarial_payroll.xlsx",
    "adversarial_resume.pdf",
    "Dockerfile",
    "deploy.sh",
    "destroy.sh",
    "index.html",
    "README.md",
])

py_binary(
    name = "app",
    srcs = ["app.py"],
    data = [
        "adversarial_banner.png",
        "adversarial_invoice.pdf",
        "adversarial_payroll.xlsx",
        "adversarial_resume.pdf",
        "index.html",
    ],
)

py_binary(
    name = "test_guardrail",
    srcs = ["test_guardrail.py"],
)
