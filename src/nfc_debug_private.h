/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __NFC_DEBUG_PRIVATE_H__
#define __NFC_DEBUG_PRIVATE_H__

#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <libgen.h>

// below define should define before blog.h
#define LOG_TAG "NFC_PLUGIN_EMUL"

#include <dlog.h>

#define LOG_COLOR_RED 		"\033[0;31m"
#define LOG_COLOR_GREEN 	"\033[0;32m"
#define LOG_COLOR_BROWN 	"\033[0;33m"
#define LOG_COLOR_BLUE 		"\033[0;34m"
#define LOG_COLOR_PURPLE 	"\033[0;35m"
#define LOG_COLOR_CYAN 		"\033[0;36m"
#define LOG_COLOR_LIGHTBLUE "\033[0;37m"
#define LOG_COLOR_END		"\033[0;m"


#define DEBUG_MSG_PRINT_BUFFER(buffer,length) \
do {\
	int i = 0;\
	LOGD(LOG_COLOR_BLUE"BUFFER =>"LOG_COLOR_END);\
	for(; i < length; i++)\
	{\
		LOGD(LOG_COLOR_BLUE" [0x%x] "LOG_COLOR_END,buffer[i]);\
	}\
	LOGD(LOG_COLOR_BLUE""LOG_COLOR_END);\
}while(0)

#define DEBUG_MSG_PRINT_BUFFER_CHAR(buffer,length) \
do {\
	int i = 0;\
	LOGD(LOG_COLOR_BLUE"BUFFER =>"LOG_COLOR_END);\
	for(; i < length; i++)\
	{\
		LOGD(LOG_COLOR_BLUE" [%c] "LOG_COLOR_END,buffer[i]);\
	}\
	LOGD(LOG_COLOR_BLUE""LOG_COLOR_END);\
}while(0)

#define DEBUG_MSG(format,args...) \
do {\
	LOGD(LOG_COLOR_CYAN" "format""LOG_COLOR_END, ##args);\
}while(0)

#define DEBUG_ERR_MSG(format,args...) \
do {\
	LOGD(LOG_COLOR_RED" "format""LOG_COLOR_END, ##args);\
}while(0)

#define DEBUG_EMUL_BEGIN() \
	do\
    {\
		LOGD(LOG_COLOR_CYAN" BEGIN >>>>"LOG_COLOR_END); \
    } while( 0 )

#define DEBUG_EMUL_END() \
	do\
    {\
		LOGD(LOG_COLOR_CYAN" END >>>>"LOG_COLOR_END); \
    } \
    while( 0 )

#define PROFILING(str) \
do{ \
	struct timeval mytime;\
	char buf[128]; = {0};\
	memset(buf, 0x00, 128);\
	gettimeofday(&mytime, NULL);\
	char time_string[128] = {0,};\
	sprintf(time_string, "%d.%4d", mytime.tv_sec, mytime.tv_usec);\
	LOGD(str); \
	LOGD("\t time = [%s]", time_string);\
}while(0)

#endif
