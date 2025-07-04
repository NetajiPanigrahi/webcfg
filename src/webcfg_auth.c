/*
 * Copyright 2020 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "webcfg_multipart.h"
#include "webcfg_auth.h"
#include "webcfg_generic.h"
#include "webcfg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
char webpa_auth_token[4096]={'\0'};
char serialNum[64]={'\0'};
/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/
static int flag_unk = 0;
/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
void execute_token_script(char *token, char *name, size_t len, char *mac, char *serNum);
/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

char* get_global_auth_token()
{
    return webpa_auth_token;
}

char* get_global_serialNum()
{
    return serialNum;
}

/*
* Fetches authorization token from the output of read script. If read script returns "ERROR"
* it will call createNewAuthToken to create and read new token
*/

void getAuthToken()
{
	//local var to update webpa_auth_token only in success case
	char output[4069] = {'\0'} ;
	char *serial_number=NULL;
	memset (webpa_auth_token, 0, sizeof(webpa_auth_token));

	if( strlen(WEBPA_READ_HEADER) !=0 && strlen(WEBPA_CREATE_HEADER) !=0)
	{
                get_deviceMAC();
                WebcfgDebug("deviceMAC: %s\n",get_deviceMAC());

		if( get_deviceMAC() != NULL && strlen(get_deviceMAC()) !=0 )
		{
			if((strlen(serialNum) ==0) || flag_unk == 1)
			{
				WebcfgInfo("getSerialNumber\n");
				serial_number = getSerialNumber();
				WebcfgInfo("SerialNumber fetched success\n");
		                if(serial_number != NULL && strlen(serial_number) > 0)
		                {
					strncpy(serialNum ,serial_number, sizeof(serialNum)-1);
					WebcfgInfo("serialNum is : %s\n", serialNum);
					WEBCFG_FREE(serial_number);
					flag_unk = 0;
		                }
				else
				{
					WebcfgError("serialNum is NULL, adding default as unknown\n");
					strncpy(serialNum ,"unknown", sizeof(serialNum)-1);
					WebcfgInfo("serialNum: %s\n", serialNum);
					flag_unk = 1;
				}
			}

			if( strlen(serialNum)>0 )
			{
				WebcfgInfo("Proceed to execute_token_script function\n");
				execute_token_script(output, WEBPA_READ_HEADER, sizeof(output), get_deviceMAC(), serialNum);
				WebcfgInfo("execute_token_script is done\n");
				if ((strlen(output) == 0))
				{
					WebcfgError("Unable to get auth token\n");
				}
				else if(strcmp(output,"ERROR")==0)
				{
					WebcfgInfo("Failed to read token from %s. Proceeding to create new token.\n",WEBPA_READ_HEADER);
					//Call create/acquisition script
					createNewAuthToken(webpa_auth_token, sizeof(webpa_auth_token), get_deviceMAC(), serialNum );
				}
				else
				{
					WebcfgInfo("update webpa_auth_token in success case\n");
					webcfgStrncpy(webpa_auth_token, output, sizeof(webpa_auth_token));
				}
			}
			else
			{
				WebcfgError("serialNum is NULL, failed to fetch auth token\n");
			}
		}
		else
		{
			WebcfgError("deviceMAC is NULL, failed to fetch auth token\n");
		}
	}
	else
	{
		WebcfgError("Both read and write file are NULL \n");
	}
}

/*
* call parodus create/acquisition script to create new auth token, if success then calls
* execute_token_script func with args as parodus read script.
*/

void createNewAuthToken(char *newToken, size_t len, char *hw_mac, char* hw_serial_number)
{
	//Call create script
	char output[12] = {'\0'};
	execute_token_script(output,WEBPA_CREATE_HEADER,sizeof(output),hw_mac,hw_serial_number);
	if (strlen(output)>0  && strcmp(output,"SUCCESS")==0)
	{
		//Call read script
		execute_token_script(newToken,WEBPA_READ_HEADER,len,hw_mac,hw_serial_number);
	}
	else
	{
		WebcfgError("Failed to create new token\n");
	}
}

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
#if 0
void execute_token_script(char *token, char *name, size_t len, char *mac, char *serNum)
{
    FILE* out = NULL, *file = NULL;
    char command[MAX_BUF_SIZE] = {'\0'};
    if(strlen(name)>0)
    {
        file = fopen(name, "r");
        if(file)
        {
            snprintf(command,sizeof(command),"%s %s %s",name,serNum,mac);
            WebcfgInfo("execute_token_script command is initiated\n");
            out = popen(command, "r");
            WebcfgInfo("execute_token_script command is executed\n");
            if(out)
            {
                fgets(token, len, out);
                pclose(out);
                WebcfgInfo("execute_token_script command is success\n");
            }
            fclose(file);
        }
        else
        {
            WebcfgError ("File %s open error\n", name);
        }
    }
}
#endif
void execute_token_script(char *token, char *name, size_t len, char *mac, char *serNum)
{
    int pipefd[2];    
    if (!token || !name || !mac || !serNum || len == 0) {
        WebcfgError("Invalid arguments to execute_token_script\n");
        if (token && len) token[0] = '\0';
        return;
    }	
	
    if (strlen(name) == 0) 
    {
        token[0] = '\0';
	return;
    }

   if (access(name, X_OK) != 0) {
	WebcfgError ("File %s open error\n", name);       
        token[0] = '\0';
        return;
    }
   
    if (pipe(pipefd) == -1)
    {
        WebcfgError("pipe creation failed: %s\n", strerror(errno));
        token[0] = '\0';
        return;
    }

    pid_t pid = fork();
    if (pid == -1)
    {
        WebcfgError("fork failed: %s\n", strerror(errno));
	close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    if (pid == 0)
    {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
	WebcfgInfo("%s command is initiated\n", __func__);
        execl(name, name, serNum, mac, NULL);
	WebcfgInfo("execute_token_script command is failed\n");
        perror("exec failed");
        _exit(1);
    }
    else
    {
	WebcfgInfo("%s command is executed\n", __func__);
        close(pipefd[1]);
        ssize_t total = 0;
        memset(token, 0, len);
	ssize_t nread = 0;
        while ((nread = read(pipefd[0], token + total, len - 1 - total)) > 0)
	{
            total += nread;
            if ((size_t)total >= len - 1)
	        break;
        }
        token[len-1] = '\0';
        close(pipefd[0]);
        int status = 0;
        waitpid(pid, &status, 0);
        /*Remove trailing newline*/
        size_t outlen = strlen(token);
        if (outlen && token[outlen - 1] == '\n') {
            token[outlen - 1] = '\0';
        }
	WebcfgInfo("%s line: %d command is success\n",__func__,__LINE__);    
    }
}
