################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../lwip/port/enet_ethernetif.c \
../lwip/port/enet_ethernetif_kinetis.c \
../lwip/port/sys_arch.c 

C_DEPS += \
./lwip/port/enet_ethernetif.d \
./lwip/port/enet_ethernetif_kinetis.d \
./lwip/port/sys_arch.d 

OBJS += \
./lwip/port/enet_ethernetif.o \
./lwip/port/enet_ethernetif_kinetis.o \
./lwip/port/sys_arch.o 


# Each subdirectory must supply rules for building sources it contributes
lwip/port/%.o: ../lwip/port/%.c lwip/port/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MK64FN1M0VLL12 -DCPU_MK64FN1M0VLL12_cm4 -DUSE_RTOS=1 -DPRINTF_ADVANCED_ENABLE=1 -DFRDM_K64F -DFREEDOM -DSERIAL_PORT_TYPE_UART=1 -DFSL_RTOS_FREE_RTOS -DSDK_DEBUGCONSOLE=1 -DCR_INTEGER_PRINTF -DPRINTF_FLOAT_ENABLE=0 -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\board" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\source" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\drivers" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\device" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\CMSIS" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\contrib\apps\tcpecho" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\port\arch" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\compat\posix\arpa" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\compat\posix\net" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\compat\posix" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\compat\posix\sys" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\compat\stdc" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\lwip" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\lwip\priv" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\lwip\prot" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\netif" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\netif\ppp" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include\netif\ppp\polarssl" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\port" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\amazon-freertos\freertos_kernel\include" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\amazon-freertos\freertos_kernel\portable\GCC\ARM_CM4F" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\utilities" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\component\serial_manager" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\component\lists" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\component\uart" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src" -I"C:\Users\HP\Documents\MCUXpressoIDE_11.6.0_8187\workspace\frdmk64f_lwip_tcpecho_freertos_myssn\lwip\src\include" -O0 -fno-common -g3 -Wall -c  -ffunction-sections  -fdata-sections  -ffreestanding  -fno-builtin -fmerge-constants -fmacro-prefix-map="$(<D)/"= -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-lwip-2f-port

clean-lwip-2f-port:
	-$(RM) ./lwip/port/enet_ethernetif.d ./lwip/port/enet_ethernetif.o ./lwip/port/enet_ethernetif_kinetis.d ./lwip/port/enet_ethernetif_kinetis.o ./lwip/port/sys_arch.d ./lwip/port/sys_arch.o

.PHONY: clean-lwip-2f-port
