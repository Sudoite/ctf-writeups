#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#define BUFSIZE 256
#define MAX_CONTACTS 511
#define COMPANY_LENGTH 0x20

#define USERNAME_LENGTH 32
#define USERNAME_LENGTH_S "32"
#define PHONE_LENGTH 10
#define PHONE_FIELD_LENGTH 16

typedef void (*exit_function_t)(int status);
typedef struct contact_data* contact_t;

struct program_data {
    contact_t contacts[MAX_CONTACTS];
    uint64_t num_contacts;

    exit_function_t exit_function;
    char company_name[COMPANY_LENGTH];
};

struct contact_data {
    uint64_t id;
    char phone[PHONE_FIELD_LENGTH];
    char username[USERNAME_LENGTH];
};

struct program_data data = {
    .company_name = "Plaid Parliament of Pwning",
    .num_contacts = 0,
    .exit_function = &exit,
};

void *xmalloc(size_t bytes) {
    void *result = malloc(bytes);
    if (result == NULL) {
        perror("xmalloc");
        exit(1);
    }
    return result;
}

contact_t find_contact(char *username) {
    for (uint64_t i=MAX_CONTACTS-1; i-->0;) {
        if (data.contacts[i] != NULL && !strncmp(data.contacts[i]->username, username, USERNAME_LENGTH)) {
            return data.contacts[i];
        }
    }
    return NULL;
}

contact_t get_contact(uint64_t id) {
    for (uint64_t i=MAX_CONTACTS-1; i-->0;) {
        if (data.contacts[i] != NULL && data.contacts[i]->id == id) {
            return data.contacts[i];
        }
    }
    return NULL;
}

bool update_id(char *username, uint64_t new_id) {
    contact_t contact = find_contact(username);
    if (contact != NULL) {
        contact->id = new_id;
        return true;
    }
    return false;
}

bool copy_username(char *dest, char *src) {
    size_t len = strnlen(src, USERNAME_LENGTH-1);
    memcpy(dest, src, len);
    return true;
}

bool copy_phone(char *dest, char *src) {
    char tmp[PHONE_LENGTH];
    uint64_t i, j;
    for (i=0, j=0; src[j] && i < PHONE_LENGTH; ++j) {
        if ('0' <= src[j] && src[j] <= '9') {
            tmp[i++] = src[j];
        }
    }
    if (i == PHONE_LENGTH) {
        memcpy(dest, tmp, PHONE_LENGTH);
        dest[PHONE_LENGTH] = '\0';
        return true;
    }
    return false;
}

bool insert_contact(contact_t contact) {
    for (uint64_t i=0; i<MAX_CONTACTS; ++i) {
        if (data.contacts[i] == NULL) {
            data.contacts[i] = contact;
            data.num_contacts++;
            return true;
        }
    }
    return false;
}

bool add_contact(uint64_t id, char *username, char *phone) {
    contact_t new_employee = xmalloc(sizeof(struct contact_data));

    contact_t old_employee = get_contact(id);
    if (old_employee != NULL) {
        free(old_employee);
        data.num_contacts--;
    }

    new_employee->id = id;
    bool success = copy_username(new_employee->username, username) &&
        copy_phone(new_employee->phone, phone);

    if (data.num_contacts >= MAX_CONTACTS || !success || !insert_contact(new_employee)) {
        free(new_employee);
        return false;
    }

    return true;
}

void exit_goodbye(int status) {
    printf("Goodbye!\n");
    exit(status);
}

void exit_save(int status) {
    // TODO implement
}

void print_prompt() {
    printf("$ ");
    fflush(stdout);
}

void print_welcome() {
    printf("Welcome to the contact manager.\n");
    printf("This program manages the contacts for %s\n", data.company_name);
    printf("Type \"help\" for a command list.\n");
    print_prompt();
}


int main(int argc, char **argv) {
    char command_buf[BUFSIZE];
    char username[USERNAME_LENGTH];
    char phone[20];
    uint64_t id;

    setbuf(stdout, NULL);

    for (print_welcome(); fgets(command_buf, BUFSIZE, stdin) != NULL; print_prompt()) {
        char *command_token = strtok(command_buf, " \n");
        char *args = strtok(NULL, "\n");
        if (!command_token) {
            continue;
        } else if (!strcmp("list", command_token)) {
            printf("Listing phone numbers not supported for security reasons.\n");
        } else if (!strcmp("get", command_token)) {
            if (args != NULL && 1 == sscanf(args, "%"SCNu64, &id)) {
                contact_t contact = get_contact(id);
                if (contact == NULL) {
                    printf("Contact not found.\n");
                } else {
                    printf("%"PRIu64": %s %s\n", contact->id, contact->username, contact->phone);
                }
            } else {
                printf("Usage: get <id>\n");
            }
        } else if (!strcmp("find", command_token)) {
            if (args != NULL) {
                contact_t contact = find_contact(args);
                if (contact == NULL) {
                    printf("Contact not found.\n");
                } else {
                    printf("%"PRIu64": %s %s\n", contact->id, contact->username, contact->phone);
                }
            } else {
                printf("Usage: find <username>\n");
            } 
        } else if (!strcmp("update-id", command_token)) {
            if (args != NULL && 2 == sscanf(args, "%" USERNAME_LENGTH_S "s %" SCNu64, username, &id)) {
                if (update_id(username, id)) {
                    printf("Successful id update.\n");
                } else {
                    printf("Failed to update id.\n");
                }
            } else {
                printf("Usage: update-id <username> <new_id>\n");
            }
        } else if (!strcmp("update-phone", command_token)) {
            if (args != NULL && 2 == sscanf(args, "%" SCNu64 "%20s", &id, phone)) {
                contact_t contact = get_contact(id);
                if (contact == NULL || !copy_phone(contact->phone, phone)) {
                    printf("Failed to update phone.\n");
                } else {
                    printf("Successful phone update.\n");
                }
            } else {
                printf("Usage: update-phone <id> <new-phone>\n");
            }
        } else if (!strcmp("add", command_token)) {
            if (args != NULL
                    && 3 == sscanf(args, "%" SCNu64 " %" USERNAME_LENGTH_S "s %20s", &id, username, phone)) {
                if (add_contact(id, username, phone)) {
                    printf("Successfully added.\n");
                } else {
                    printf("Failed to add.\n");
                }
            } else {
                printf("Usage: add <id> <username> <phone>\n");
            }
        } else if (!strcmp("quit", command_token)) {
            break;
        } else if (!strcmp("exit-mode", command_token)) {
            char *type = args;
            if (!type) {
                printf("You must specify an exit mode.\n");
            } else if (!strcmp("default", type)) {
                data.exit_function = &exit;
                printf("Changed exit mode to default.\n");
            } else if (!strcmp("save", type)) {
                printf("Saving not supported yet.\n");
            } else if (!strcmp("goodbye", type)) {
                data.exit_function = &exit_goodbye;
                printf("Changed exit mode to goodbye.\n");
            } else {
                printf("Exit mode not recognized.\n");
            }
        } else {
            printf(
                "Possible commands:\n"
                "\tlist                                 list all contacts\n"
                "\tget <id>                             get a contact by id\n"
                "\tfind <username>                      get a contact by name\n"
                "\tupdate-id <username> <new-id>        update the id when an employee changes departments\n"
                "\tupdate-phone <id> <new-phone>        update the phone-number of an employee\n"
                "\tadd <id> <username> <phone>          add a new employee\n"
                "\texit-mode <default|save|goodbye>     choose how to exit\n"
                "\tquit\n");

        }
    }

    data.exit_function(0);
    return 0;
}
