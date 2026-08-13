#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct message {
    size_t len;
    char *data;
};

static char global_buf[5] = {1};
static char global_bss[5];

static struct message *message_create(const char *text)
{
    struct message *msg = malloc(sizeof(*msg));
    if (msg == NULL)
        return NULL;

    msg->len = strlen(text);
    msg->data = malloc(msg->len + 1);
    if (msg->data == NULL) {
        free(msg);
        return NULL;
    }

    memcpy(msg->data, text, msg->len + 1);
    return msg;
}

static void message_destroy(struct message *msg)
{
    if (msg == NULL)
        return;

    free(msg->data);
    free(msg);
}

static void normal(void)
{
    struct message *msg = message_create("hello world");
    printf("%s\n", msg->data);
    message_destroy(msg);
}

static void overflow(void)
{
    struct message *msg = message_create("hello");

    /* 6 bytesしか確保されていない */
    volatile char *p = msg->data;
    p[6] = 'X';

    message_destroy(msg);
}

static void underflow(void)
{
    struct message *msg = message_create("hello");

    volatile char *p = msg->data;
    p[-1] = 'X';
}

static void partial_overflow(void)
{
    char *buf = malloc(5);
    volatile int *p = (int *)(buf + 3);

    *p = 1;
}

static void global_overflow(void)
{
    volatile char *p = global_buf;
    p[5] = 'X';
}

static void global_underflow(void)
{
    volatile char *p = global_buf;
    p[-1] = 'X';
}

static void global_bss_overflow(void)
{
    volatile char *p = global_bss;
    p[5] = 'X';
}

static void use_after_free(void)
{
    struct message *msg = message_create("hello");
    char *data = msg->data;

    message_destroy(msg);

    volatile char c = data[0];
    printf("%c\n", c);
}

static void double_free(void)
{
    char *buf = malloc(128);

    free(buf);
    free(buf);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr,
                "usage: %s normal|overflow|underflow|partial-overflow|global-overflow|global-underflow|global-bss-overflow|uaf|double-free\n",
                argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "normal") == 0)
        normal();
    else if (strcmp(argv[1], "overflow") == 0)
        overflow();
    else if (strcmp(argv[1], "underflow") == 0)
        underflow();
    else if (strcmp(argv[1], "partial-overflow") == 0)
        partial_overflow();
    else if (strcmp(argv[1], "global-overflow") == 0)
        global_overflow();
    else if (strcmp(argv[1], "global-underflow") == 0)
        global_underflow();
    else if (strcmp(argv[1], "global-bss-overflow") == 0)
        global_bss_overflow();
    else if (strcmp(argv[1], "uaf") == 0)
        use_after_free();
    else if (strcmp(argv[1], "double-free") == 0)
        double_free();
    else {
        fprintf(stderr, "unknown test: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
