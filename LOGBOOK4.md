# **Week #4**

## **SEEDs Lab**

https://seedsecuritylabs.org/Labs_20.04/Software/Environment_Variable_and_SetUID/

## Task 1 - Manipulating Environment Variables

<br>

![screenshot1](screenshots/LOGBOOK4/screenshot1.png)

Using the printenv or env command will print out the enviromnet variables.

---

![screenshot2](screenshots/LOGBOOK4/screenshot2.png)

Export will set an environmnet variable and unset will remove it.

<br>

## Task 2 - Passing Environment Variables from Parent Process to Child Process

<br>

![screenshot3](screenshots/LOGBOOK4/screenshot3.png)

Compiling the child process version.

---

![screenshot4](screenshots/LOGBOOK4/screenshot4.png)

Running the child process version and saving the environment variables into a file.

---

![screenshot5](screenshots/LOGBOOK4/screenshot5.png)

Compiling the parent process version.

---

![screenshot6](screenshots/LOGBOOK4/screenshot6.png)

Running the parent process version and saving the environment variables into a file.

---

![screenshot7](screenshots/LOGBOOK4/screenshot7.png)

Comparing both processes environment variables variables with the command "diff".

---

### Conclusion: 
The environment variables for a parent process and its child process are the same

<br>

## Task 3 - Environment Variables and execve()

<br>

![screenshot8](screenshots/LOGBOOK4/screenshot8.png)

Compiling and running "myenv.c". Nothing gets printed.

---

![screenshot9](screenshots/LOGBOOK4/screenshot9.png)

Compiling and running "myenv.c" with alterations. Program prints environment variables.

---

### Conclusion:
If the third parameter in the invocation of execve() is set to "NULL", the program doesn't have access to the environment variables, therefore the program couldn't print anything. If the third parameter in the invocation of execve() is set to "environ" then the program has access to the environment variables and prints it.

<br>

## Task 4 - Environment Variables and system()

<br>

![screenshot10](screenshots/LOGBOOK4/screenshot10.png)

Compiling and running "task4.c" program. Prints the environment variables.

---

### Conclusion:
The "system" function uses "execl", which in its turn calls "execve" with the parent's process environment variables, which finally executes "/bin/sh" with the argument passed to "system" and prints the environment variables value.

<br>

## Task 5 - Environment Variable and Set-UID Programs

<br>

![screenshot11](screenshots/LOGBOOK4/screenshot11.png)

Compiling "task5.c" program and setting environment variables values.

---

![screenshot12](screenshots/LOGBOOK4/screenshot12.png)

Running "task5.c" program and seeing the values of environment variables that were changed.

---

### Conclusion:
After performing all the steps, we were able to view the three environment variables (PATH, LD_LIBRARY_PATH e the created variable THE_NAME) with the values ​​we entered.

<br>

## Task 6 - The PATH Environment Variable and Set-UID Programs

<br>

![screenshot13](screenshots/LOGBOOK4/screenshot13.png)

Disabling Set-UID protection and setting path.

---

![screenshot14](screenshots/LOGBOOK4/screenshot14.png)

Compiling Set-UID program.

---

![screenshot15](screenshots/LOGBOOK4/screenshot15.png)

Compiling Malicious program.

---

![screenshot16](screenshots/LOGBOOK4/screenshot16.png)

Running Set-UID program.

---

### Conclusion: 
Calling system in a Set-UID program enables users to control the program through environment variables. By setting "/home/seed" in PATH and by having "ls" program being called with relative path in system call, we can make the Set-UID program run our version of "ls" as long as our malicious code is located in the path we specified earlier. So when we ran the program, instead of a list of files in a directory, we saw the message "HACKED!" printed on the screen, meaning our version of "ls" was the one executed.
