---
layout: post
title: UDR MMI
img: "https://github.com/laigasus/laigasus.github.io/blob/main/assets/img/posts_resource/mmi_result.png?raw=true"
date: July, 08 2021
tags: [Socket, Linux]
---

# UDR MMI



### 개요

규모: 3인<br>
기술 스택: C<br>
개발환경: 온라인 IDE(Cocalc)<br>
기한: 1주(2021.07)<br>



### 로직

![mmi_logic](https://github.com/laigasus/laigasus.github.io/blob/main/assets/img/posts_resource/mmi_logic.png?raw=true)



### 결과

![mmi_result](https://github.com/laigasus/laigasus.github.io/blob/main/assets/img/posts_resource/mmi_result.png?raw=true)



### 소스코드

#### agtd.c

```c
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define CMD_FUNC 3
// 192.168.1.128, 192.168.1.145

typedef struct msgq_data {
  long type;
  char text[2048];
} Message;

int socket_open(char* target) {
  int sock, target_port;

  if (!strcmp(target, "mmi")) {
    target_port = 9000;
  }
  if (!strcmp(target, "stdby")) {
    target_port = 9001;
  }
  struct sockaddr_in serv_addr = {.sin_family = AF_INET,
                                  .sin_addr.s_addr = htonl(INADDR_ANY),
                                  .sin_port = htons(target_port)};

  sock = socket(PF_INET, SOCK_STREAM, 0);
  if (sock < 0) return -1;

  if (bind(sock, (struct sockaddr*)&serv_addr, sizeof serv_addr) < 0) return -2;

  if (listen(sock, 5) < 0) return -3;

  return sock;
}

int mmi_server_worker(int clnt_sock, char* buf) {
  int i = 0;
  bool flag = false;
  char* arg[3] = {"", "", ""};
  char send_buf[2048] = "";
  char* cmd_list[CMD_FUNC] = {"MEMORY", "DISK", "CPU"};
  int rstat_queue, prm_queue, len;

  // 아규먼트 토큰 분리
  for (char* p = strtok(buf, "\n"); p; p = strtok(NULL, "\n")) {
    arg[i++] = p;
  }
  printf("토큰 분리 성공\n");

  Message send_data = {1L, *arg[1]};
  Message recv_data;
  memset(&recv_data, 0x00, sizeof(recv_data));

  printf("%s\n", arg[0]);
  printf("%s\n", arg[1]);

  //아규먼트 별 명령 실행
  if (!strcmp(arg[0], "DIS-RESOURCE")) {
    i = 0;
    do {
      if (!strcmp(arg[1], cmd_list[i])) {
        flag = true;
        break;
      }
      i++;
    } while (i < CMD_FUNC);
    if (flag) {
      if ((rstat_queue = msgget((key_t)0111, IPC_CREAT | 0666)) == -1) {
        perror("메시지 큐 생성 실패\n");
      }
      printf("memory 실행\n");
      sprintf(send_data.text, "%s", arg[1]);
      printf("%s\n", send_data.text);
      printf("send 실행\n");
      if (msgsnd(rstat_queue, &send_data, strlen(send_data.text), 0) == -1) {
        perror("메시지 큐 전송 실패\n");
      }
      printf("rcv 실행\n");
      if ((len = msgrcv(rstat_queue, &recv_data, 100, 0, 0)) == -1) {
        perror("메시지 큐 수신 실패\n");
      }
      sprintf(send_buf, "%s", recv_data.text);
      // if (msgctl(rstat_queue, IPC_RMID, 0) == -1) {
      // perror("msgctl 실패\n");
      //}
    } else {
      char msg[30] = "명령어 잘못 입력\n";
      sprintf(send_buf, "%s", msg);
    }

  } else if (!strcmp(arg[0], "DIS-SW-STS")) {
    if ((prm_queue = msgget((key_t)1112, IPC_CREAT | 0666)) == -1) {
      perror("메시지 큐 생성 실패\n");
    }
    printf("ACT 실행\n");
    sprintf(send_data.text, "%s", arg[1]);
    if (msgsnd(prm_queue, &send_data, strlen(send_data.text), 0) == -1) {
      perror("메시지 큐 전송 실패\n");
    }
    if (msgrcv(prm_queue, &recv_data, 100, 0, 0) == -1) {
      perror("메시지 큐 수신 실패\n");
    }
    sprintf(send_buf, "%s", recv_data.text);
  }
  write(clnt_sock, send_buf, strlen(send_buf));
  close(clnt_sock);
}

void main() {
  // 서버 오픈, accept에 사용 할 변수 선언, read에 사용 할 변수 선언
  int mmi_client_socket;
  struct sockaddr_in clnt_addr;
  int clnt_addr_size;
  int mmi_server_socket = socket_open("mmi"), recv_len;  // 서버 오픈 함수
  char buf[2048];

  switch (mmi_server_socket) {
    case -1:
      perror("소켓 생성 실패\n");
      exit(-1);
    case -2:
      perror("바인드 실패\n");
      exit(-2);
    case -3:
      perror("listen 실패\n");
      exit(-3);
  }

  while (1) {
    clnt_addr_size = sizeof(clnt_addr);
    mmi_client_socket = accept(mmi_server_socket, (struct sockaddr*)&clnt_addr,
                               &clnt_addr_size);
    printf("mmi 연결 성공\n");
    recv_len = read(mmi_client_socket, buf, sizeof buf);
    if (recv_len < 0) continue;
    buf[recv_len] = '\0';
    printf("%s\n", buf);

    mmi_server_worker(mmi_client_socket, buf);  //받은 명령어 실행 코드
  }
}
```



#### mmi.c

```c
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

void send_cmd(const char *cmd) {
  int conn_repeat = 0;
  char *ip_list[] = {"192.168.127.234"};

  struct sockaddr_in addr = {.sin_family = AF_INET,
                             .sin_addr.s_addr = inet_addr(ip_list[conn_repeat]),
                             .sin_port = htons(9000)};
  int addr_len = sizeof addr, recv_len;
  char buf[2048];
  int fd = socket(PF_INET, SOCK_STREAM, 0);
  bool conn_flag = false;

  do {
    if (connect(fd, (struct sockaddr *)&addr, addr_len) == -1) {
      conn_repeat++;
      printf("Change Connect..<%s>\t", ip_list[conn_repeat]);
      printf("repeat: %d\n", conn_repeat);
      addr.sin_addr.s_addr = inet_addr(ip_list[conn_repeat]);
      conn_flag = true;
    } else {
      conn_flag = false;
    }
  } while (conn_flag);

  write(fd, cmd, strlen(cmd));
  recv_len = read(fd, buf, sizeof buf);
  printf("%s\n", buf);
  close(fd);
}

void main(int argc, char *argv[]) {
  char cmd[2048] = "";
  int i;
  for (i = 1; i < argc; i++) {
    strcat(cmd, argv[i]);
    strcat(cmd, "\n");
  }
  send_cmd(cmd);
}
```



#### rstat.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>

#define BUFSIZE 40
#define QKEY (key_t)0111

typedef struct msgq_data {
  long type;
  char text[BUFSIZE];
} Message;

void main() {
  int qid, len;
  char tmp[2048];
  char fcnt[BUFSIZE] = "";
  FILE* fp;

  printf("msgq 생성\n");
  if ((qid = msgget(QKEY, IPC_CREAT | 0666)) == -1) {
    perror("msgget failed");
    exit(1);
  }
  while (1) {
    Message recv_data, send_data;
    memset(&recv_data, 0x00, sizeof(recv_data));

    if ((len = msgrcv(qid, &recv_data, BUFSIZE, 0, 0)) == -1) {
      perror("msgrcv failed");
      exit(1);
    }

    printf("%s = 받은 문자값\n", recv_data.text);
    printf("%s\n", recv_data.text);

    if (strcmp(recv_data.text, "CPU") == 0) {
      fp = popen("top -n 1 -b | awk '/^%Cpu/{print $2}'", "r");
    } else if (strcmp(recv_data.text, "MEMORY") == 0) {
      fp = popen("free | grep Mem | awk '{print $4/$3 * 100.0}'", "r");
    } else if (strcmp(recv_data.text, "DISK") == 0) {
      fp = popen("df|tail -1|tr -s ' '|cut -d ' ' -f5", "r");
    }
    fgets(fcnt, sizeof fcnt, fp);
    printf("%s", fcnt);
    send_data.type = 1;
    sprintf(send_data.text, "%s", fcnt);
    msgsnd(qid, &send_data, strlen(send_data.text), 0);
  }
}
```



#### prm.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>

#define BUFSIZE 40
#define QKEY (key_t)1112

typedef struct msgq_data {
  long type;
  char text[BUFSIZE];
} Message;

void main() {
  int qid, len;
  char tmp[2048];
  char fcnt[BUFSIZE] = "";
  FILE* fp;

  printf("msgq 생성\n");
  if ((qid = msgget(QKEY, IPC_CREAT | 0666)) == -1) {
    perror("msgget failed");
    exit(1);
  }
  while (1) {
    Message recv_data, send_data;
    memset(&recv_data, 0x00, sizeof(recv_data));

    if ((len = msgrcv(qid, &recv_data, BUFSIZE, 0, 0)) == -1) {
      perror("msgrcv failed");
      exit(1);
    }

    printf("%s = 받은 문자값\n", recv_data.text);
    printf("%s\n", recv_data.text);

    if (!strcmp(recv_data.text, "ACT")) {
      fp = popen("./rstat", "r");
      fp = popen("ps -ef | grep rstat | head -1 | tr -s ' ' | cut -d ' ' -f8", "r");
      printf("rstat is running");
    } else if (!strcmp(recv_data.text, "SBY")) {
      fp = popen("killall -9 rstat", "r");
      fp = popen("ps -ef | grep rstat | head -1 | tr -s ' ' | cut -d ' ' -f8", "r");
      printf("rstat is killed");
    }
    fgets(fcnt, sizeof fcnt, fp);
    printf("%s", fcnt);
    send_data.type = 1;
    sprintf(send_data.text, "%s", fcnt);
    msgsnd(qid, &send_data, strlen(send_data.text), 0);
  }
}

// agtd 두개의 rstat은 동일한 이름과 역할을 수행한다.
// 두개의 rstat을 구분해서 파악하려면 프로세스 이름이 아닌 pid로 구분을 한다
// rstat 프로세스 상태를 확인하려면 getpid()를 사용한다.
// 사전에 rstat에서 getpid()로 실행하여 메세지큐로 prm에 전달되어 있어야 한다
// rstat와 prm은 독립적으로 실행시키는 것이 아닌 agtd가 활성화 되었을때
// 가동한다(자원 낭비 방지) popen으로 awk를 사용하여 결과 fcnt출력값이 없으면
// killed, 있으면 running을 agtd에게 전달한다.
```



#### 프로젝트(Github)

[laigasus/MMI-EMS-emsd: 아리아텍 실습 (github.com)](https://github.com/laigasus/MMI-EMS-emsd)
