// dlopen — send the APPLY (1) or COMMIT (2) control signal to a running target PID.
#include <csignal>
#include <iostream>
#include <cstdlib>
#include <unistd.h>

static int pick_signal(int choice){
    int base = SIGRTMIN;
    int off_apply  = 10;
    int off_commit = 11;
    if (const char* a = std::getenv("DIBE_SIG_APPLY"))  off_apply  = std::atoi(a);
    if (const char* c = std::getenv("DIBE_SIG_COMMIT")) off_commit = std::atoi(c);

    if (choice == 1) return base + off_apply;   // APPLY
    if (choice == 2) return base + off_commit;  // COMMIT
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <PID> <1|2>\n"
                  << "  1 -> APPLY (SIGRTMIN+off_apply)\n"
                  << "  2 -> COMMIT (SIGRTMIN+off_commit)\n";
        return 1;
    }

    pid_t target_pid = static_cast<pid_t>(std::atoi(argv[1]));
    int choice = std::atoi(argv[2]);
    int sig = pick_signal(choice);
    if (sig == 0) {
        std::cerr << "Invalid option: " << argv[2] << std::endl;
        return 1;
    }

    if (kill(target_pid, sig) == -1) {
        perror("Failed to send signal");
        return 1;
    }

    std::cout << "Sent RT signal " << sig << " to process " << target_pid << std::endl;
    return 0;
}
