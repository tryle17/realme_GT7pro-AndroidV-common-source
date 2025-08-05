#!/bin/bash
FILE_TO_CHECK="../drivers/starkernel/Kconfig"
if [ -f "$FILE_TO_CHECK" ]; then
    cat << EOF > ../out/temp_config
config STAR_KERNEL
    bool "Determine whether it is a StarKernel"
    default y
    help
    This is the custom Kconfig for StarKernel.
EOF
else
    cat << EOF > ../out/temp_config
config STAR_KERNEL
    bool "Determine whether it is a StarKernel"
    default n
    help
    This is the custom Kconfig for StarKernel.
EOF
fi
