LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := mh1721crypto
LOCAL_SRC_FILES := src/bn.c src/sha256.c src/random.c src/rsa.c src/mh1721_jni.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CFLAGS := -Wall -Wextra -O2 -fvisibility=hidden
include $(BUILD_SHARED_LIBRARY)
