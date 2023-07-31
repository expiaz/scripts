
void parse_tokens(char *body, char *delimiter) {
    char *tokens[5], *t;
    int i, j, l;

    for (i=0;i<5;i++) tokens[i] = (char *) 0x0;
    l = strlen(delimiter);
    t = delimiter;
    i = 0;
    while (*body) {
        if (*body == *t) {
            //printf("------ CHRTK %c\n", *t);
            //t++;
            if (! *++t) {
                if (tokens[i]) {
                    //printf("------ END AT %s\n", body + 1);
                    *(body - l + 1) = '\0';
                    i++;
                } else {
                    tokens[i] = body + 1;
                    //printf("-------- START AT %s\n", body + 1);
                }
                t = delimiter;
            }
        } else
            t = delimiter;
        body++;
    }

    for (i--; i >= 0; i--) {
        printf("%s\n",tokens[i]);
    }
}

int main(int argc, char **argv) {
    parse_tokens(argv[1], argv[2]);
}