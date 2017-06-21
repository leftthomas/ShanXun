#include <iostream>
#include "md5.h"
#include <assert.h>
using namespace std;

char res[35];

static void getPIN(char *userName, char *PIN)
{
    int i,j;//循环变量
    long timedivbyfive;//时间除以五
    time_t timenow;//当前时间，从time()获得
    char RADIUS[16]="singlenet01";//凑位字符
    char timechar[4];//时间 div 5
    char beforeMD5[32];//时间 div 5+用户名+凑位
    CMD5 md5;//MD5结构体
    char afterMD5[16];//MD5输出
    char MD501[3];
    char timeHash[4]; //时间div5经过第一次转后后的值
    char temp[32]; //第一次转换时所用的临时数组
    char PIN27[6]; //PIN的2到7位，由系统时间转换

    timenow = time(NULL);

    //timenow = 1111111111;

    timedivbyfive = timenow / 5;

    for(i = 0; i < 4; i++) {
        timechar[i] = (char)(timedivbyfive >> (8 * (3 - i)) & 0xFF);
    }
    for(i = 0; i < 4; i++) {
        beforeMD5[i]= timechar[i];
    }
    for(i = 4; i < 16 && userName[i-4]!='@' ; i++) {
        beforeMD5[i] = userName[i-4];
    }

    j=0;

    while(RADIUS[j]!='\0')
    {
        beforeMD5[i++] = RADIUS[j++];
    }

    md5.GenerateMD5((unsigned char *)beforeMD5,i);

    string t=md5.ToString();

    for(int i=0;i<16;i++)
        afterMD5[i]=t[i];

    MD501[0]=t[0];
    MD501[1]=t[1];

    for(i = 0; i < 32; i++) {
        temp[i] = timechar[(31 - i) / 8] & 1;
        timechar[(31 - i) / 8] = timechar[(31 - i) / 8] >> 1;
    }

    for (i = 0; i < 4; i++) {
        timeHash[i] = temp[i] * 128 + temp[4 + i] * 64 + temp[8 + i]
                                                         * 32 + temp[12 + i] * 16 + temp[16 + i] * 8 + temp[20 + i]
                                                                                                       * 4 + temp[24 + i] * 2 + temp[28 + i];
    }

    temp[1] = (timeHash[0] & 3) << 4;
    temp[0] = (timeHash[0] >> 2) & 0x3F;
    temp[2] = (timeHash[1] & 0xF) << 2;
    temp[1] = (timeHash[1] >> 4 & 0xF) + temp[1];
    temp[3] = timeHash[2] & 0x3F;
    temp[2] = ((timeHash[2] >> 6) & 0x3) + temp[2];
    temp[5] = (timeHash[3] & 3) << 4;
    temp[4] = (timeHash[3] >> 2) & 0x3F;

    for (i = 0; i < 6; i++) {
        PIN27[i] = temp[i] + 0x020;
        if(PIN27[i]>=0x40) {
            PIN27[i]++;
        }
    }

    PIN[0] = '\r';
    PIN[1] = '\n';

    memcpy(PIN+2, PIN27, 6);

    PIN[8] = MD501[0];
    PIN[9] = MD501[1];

    strcpy(PIN+10, userName);
}

unsigned char ToHex(unsigned char x)
{
    return  x > 9 ? x + 55 : x + 48;
}

std::string UrlEncode(const std::string& str)
{
    std::string strTemp = "";
    size_t length = str.length();
    for (size_t i = 0; i < length; i++)
    {
        if (isalnum((unsigned char)str[i]) ||
            (str[i] == '-') ||
            (str[i] == '_') ||
            (str[i] == '.') ||
            (str[i] == '~'))
            strTemp += str[i];
        else if (str[i] == ' ')
            strTemp += "+";
        else
        {
            strTemp += '%';
            strTemp += ToHex((unsigned char)str[i] >> 4);
            strTemp += ToHex((unsigned char)str[i] % 16);
        }
    }
    return strTemp;
}


int main(int argc,char *argv[])
{

//    char beforeMD5[32]="1538114646511111111111111111111";//时间 div 5+用户名+凑位
//    CMD5 md5;//MD5结构体
//
//    md5.GenerateMD5((unsigned char *)beforeMD5,26);
//
//    cout<<md5.ToString()<<endl;

    getPIN("15381146465@GDPF.XY",res);

    //cout<<res<<endl;
    string password="111137";
    string real=UrlEncode(res);

    cout<<real<<endl;

    string mend="-G -H \"Referer: http://192.168.1.1/userRpm/PPPoECfgRpm.htm\" -H \"Cookie: Authorization=Basic\"%\"20YWRtaW46MTIzNDU2; ChgPwdSubTag=\" -H \"Connection: keep-alive\" --compressed";

    string head=" \"http://192.168.1.1/userRpm/PPPoECfgRpm.htm?acc="+real;
    head+="&psw="+password+"&confirm="+password+"&wan=0&wantype=2&specialDial=100&SecType=1&sta_ip=0.0.0.0&sta_mask=0.0.0.0&linktype=4&waittime2=0&Connect=%C1%AC+%BD%D3\"";

    system(("curl "+head+mend).data());
    return 0;
}
