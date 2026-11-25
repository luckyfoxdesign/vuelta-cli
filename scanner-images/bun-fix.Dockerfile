ARG BASE_IMAGE
FROM ${BASE_IMAGE}

# No project or package scripts enter this image. Repair commands always use
# --ignore-scripts and the core's restricted registry proxy.
USER 10001:10001
ENTRYPOINT []
CMD ["bun", "--version"]
