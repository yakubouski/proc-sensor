#pragma once
#include <sys/ioctl.h> //ioctl() and TIOCGWINSZ
#include <unistd.h> // for STDOUT_FILENO
#include <csignal>
#include <cstdio>
// ...

/*
- Position the Cursor:
  \033[<L>;<C>H
	 Or
  \033[<L>;<C>f
  puts the cursor at line L and column C.
- Move the cursor up N lines:
  \033[<N>A
- Move the cursor down N lines:
  \033[<N>B
- Move the cursor forward N columns:
  \033[<N>C
- Move the cursor backward N columns:
  \033[<N>D

- Clear the screen, move to (0,0):
  \033[2J
- Erase to end of line:
  \033[K

- Save cursor position:
  \033[s
- Restore cursor position:
  \033[u
*/

namespace ci {
	class cconsole {
		static inline void move(int x, int y) {
			"\033[<L>;<C>H";
		}
	private:
		static void size(ssize_t& width,ssize_t& height) {
			struct winsize size;
			ioctl(STDOUT_FILENO, TIOCGWINSZ, &size);
			width = size.ws_col;
			height = size.ws_row;
		}
		//SIGWINCH
	public:
		static ssize_t run() {
            int sig_numbers[]{ SIGWINCH, SIGUSR1, SIGINT, SIGSEGV, SIGQUIT, SIGABRT };
            sigset_t sig_list;
            sigemptyset(&sig_list);
            for (auto& s : sig_numbers) {
                sigaddset(&sig_list, s);
            }
            sigprocmask(SIG_SETMASK, &sig_list, nullptr);

            for (int sig = 0; sigwait(&sig_list, &sig) == 0; sig = 0) {
                switch (sig) {
                case SIGUSR1:
                    continue;
                case SIGWINCH:
                {
                    ssize_t w, h;
                    size(w, h);
                    printf("Window-Resize (%ldx%ld)\n", w,h);
                    continue;
                }
                default:
                    printf("\nSIGNAL: %ld raised. Terminate.\n", sig);
                    break;
                }
                break;
            }

		}
	};
}