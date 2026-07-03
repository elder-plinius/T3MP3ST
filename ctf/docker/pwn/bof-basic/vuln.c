/*
 * T3MP3ST CTF - Buffer Overflow Challenge
 *
 * Vulnerability: Stack buffer overflow in vuln()
 * Protections: None (no canary, no PIE, NX disabled)
 * Objective: Redirect execution to win() function
 *
 * DO NOT USE IN PRODUCTION - Intentionally vulnerable
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Disable buffering
void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

// Win function - prints the flag
void win() {
    FILE *f = fopen("/challenge/flag.txt", "r");
    if (f == NULL) {
        printf("Error: Could not open flag file\n");
        return;
    }

    char flag[128];
    if (fgets(flag, sizeof(flag), f) != NULL) {
        printf("\n[+] ACCESS GRANTED\n");
        printf("[+] FLAG: %s\n", flag);
    }
    fclose(f);
    exit(0);
}

// Vulnerable function
void vuln() {
    char buffer[64];

    printf("╔════════════════════════════════════════╗\n");
    printf("║     SECURE TERMINAL ACCESS SYSTEM      ║\n");
    printf("╚════════════════════════════════════════╝\n");
    printf("\nEnter access code: ");

    // VULNERABLE: gets() does not check buffer bounds
    gets(buffer);

    printf("\nAccess code received: %s\n", buffer);
    printf("[-] ACCESS DENIED\n");
}

int main() {
    setup();

    printf("\n[*] Terminal initialized\n");
    printf("[*] win() function at: %p\n", win);  // Hint for players

    vuln();

    return 0;
}
