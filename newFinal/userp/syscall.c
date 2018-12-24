#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
//Shivam implimentation 20/11
#include "threads/vaddr.h"
#include "list.h"
#include "process.h"
#include "threads/synch.h"



static void syscall_handler (struct intr_frame *);
//Shivam implimentation task 2 11/20
void verifyAddress(const void *);
struct fileStructute* searchList(struct list* filesList, int fd);
static struct semaphore fileSystemSema;

struct fileStructute{
	struct file* ptr;
	int fd;
	struct list_elem element;
}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  sema_init(&fileSystemSema, 1);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	//Shivam implimentation task 2 and 3 11/20
  //printf ("system call!\n");
  //thread_exit ();
	verifyAddress(f->esp);

	int systemCall = *(f->esp);

	switch(systemCall){
		
		case SYS_EXIT:
			verifyAddress(f->esp + 4);
			processExit(*((int *)(f->esp +4)));
			break;

		case SYS_READ:
			verifyAddress(f->esp + 28);
			verifyAddress(f->esp + 24);
			if(*(f->esp + 20) == 0){
				unit8_t* buffer = *((int *)(f->esp + 24));

				for(int i = 0; i < *((int *)(f->esp + 28)); i++){
					buffer[i] = input_gcc();
				}

				f->eax = *((int *)(f->esp + 28));

			}else{

				struct fileStructre *filePtr = searchList(&thread_current()->filesList, *((int *)(f->esp + 20)));
				if(NULL != filePtr){
					sema_down(&fileSystemSema);
					f->eax = file_read(filePtr->ptr, *((int *)(f->esp + 24)), *((int *)(f->esp + 28)));
					sema_up(&fileSystemSema);
				}else{
					f->eax = -1;
				}
			}

			break;

		case SYS_WRITE:
			verifyAddress(f->esp + 28);
			verifyAddress(f->esp + 24);
			if(*(f->esp + 20) == 1){
				putbuf(*((int *)(f->esp + 24)), *((int *)(f->esp + 28)));

				f->eax = *((int *)(f->esp + 28));

			}else{

				struct fileStructre *filePtr = searchList(&thread_current()->filesList, *((int *)(f->esp + 20)));
				if(NULL != filePtr){
					sema_down(&fileSystemSema);
					f->eax = file_write(filePtr->ptr, *((int *)(f->esp + 24)), *((int *)(f->esp + 28)));
					sema_up(&fileSystemSema);
				}else{
					f->eax = -1;
				}
			}

			break;

		case SYS_HALT:
			shutdown_power_off();
			break;

		case SYS_EXEC:
			verifyAddress(f->esp + 4);
			verifyAddress(*((int *)(f->esp + 4)));
			f->eax = processExecute(*((int *)(f->esp + 4)));
			break;

		case SYS_WAIT:
			verifyAddress(f->esp + 4);
			f->eax = process_wait(*((int *)(f->esp + 4)));
			break;

		case SYS_FILESIZE:
			verifyAddress(f->esp + 4);
			sema_down(&fileSystemSema);
			f->eax = file_length(searchList(&thread_current->filesList, *((int *)(f->esp +4))));
			sema_up(&fileSystemSema);
			break;

		case SYS_SEEK:
			verifyAddress(f->esp + 20);
			sema_down(&fileSystemSema);
			file_seek(searchList(&thread_current->filesList, *((int *)(f->esp +16)))->ptr, *((int *)(f->esp +20)));
			sema_up(&fileSystemSema);
			break;

		case SYS_TELL:
			verifyAddress(f->esp + 4);
			sema_down(&fileSystemSema);
			f->eax = file_tell(searchList(&thread_current->filesList, *((int *)(f->esp +4))));
			sema_up(&fileSystemSema);
			break;

		case SYS_CLOSE:
			verifyAddress(f->esp + 4);
			sema_down(&fileSystemSema);
			
			struct list_elem* element;
			
			element = list_begin(&thread_current->filesList);
			
			while(element != list_end(&thread_current->filesList)){
				struct fileStructure* newFile = list_entry(element, struct fileStructre, element);
				if(newFile->fd == *((int *)(f->esp +4))){
					file_close(newFile->ptr);
					list_remove(element);
					break;
				}
				element = list_next(element);
			}
			free(element);

			sema_up(&fileSystemSema);
			break;

		case SYS_CREATE:
			verifyAddress(* (int *)(f->esp + 16));
			verifyAddress(f->esp + 20);
			sema_down(&fileSystemSema);
			f->eax = filesys_create(*((int *)(f->esp + 16)), *((int *)(f->esp + 20)));
			sema_up(&fileSystemSema);
			break;

		case SYS_REMOVE:
			verifyAddress(f->esp + 4);
			verifyAddress(* (int *)(f->esp + 4));
			sema_down(&fileSystemSema);
			if(NULL != filesys_remove(* (int *)(f->esp + 4))){
				f->eax = true;
			}else{
				f->eax = false;
			}
			sema_up(&fileSystemSema);
			break;

		case SYS_OPEN:
			verifyAddress(f->esp + 4);
			verifyAddress(* (int *)(f->esp + 4));
			sema_down(&fileSystemSema);
			struct file* filePtr = filesys_open(* (int *)(f->esp + 4));
			sema_up(&fileSystemSema);

			if(NULL != filePtr){
				struct fileStructure* filePtr1;
				filePtr1 = malloc(sizeof(*filePtr1));
				filePtr1->ptr = filePtr;
				filePtr1->fd = &thread_current()->fd_count;
				f->eax = filePtr1->fd;
				&thread_current()->fd_count++;
				list_push_back(&thread_current()->filesList, &filePtr1->element);
			}else{
				f->eax = -1;
			}
			break;

	}
}

void verifyAddress(const void *address){

	if(!is_user_vaddr(address)){
		//invalid address hence exit process
		processExit(-1);
		return;

	}

	if(NULL == pagedir_get_page(thread_current()->pagedir, vaddr)){
		//pafe fault hence exit
		processExit(-1);
		return;
	}
}

void processExit(int exitValue){
	struct list_elem *element;

	element = list_begin(&thread_current()->parentThreadPtr->childProcessesList);

	while(element != list_end(&thread_current()->parentThreadPtr->childProcessesList)){
		struct child *childPtr = list_entry(element, struct child, element);

		if(childPtr->threadID == thread_current()->tid){
			childPtr->used = true;
			childPtr->errorValue = exitValue;
		}

		element = list_next(element);
	}

	thread_current()->errorValue = exitValue;

	if(exitValue == -100){
		processExit(-1);
	}

	file_close(&thread_current()->ownFile);
	closeFiles(&thread_current()->filesList);

	if(thread_current()->parentThreadPtr->waitFortid == thread_current()->tid){
		sema_up(&thread_current()->parentThreadPtr->childSema);
	}

	thread_exit();
}

int processExecute(* fileName){

	sema_down(&fileSystemSema);

	char *token = malloc(strlen(fileName)+1);
	strlcpy(token,fileName,strlen(fileName)+1);

	char *dummy;
	token = strtok_r(fileName," ",&dummy);

	struct file *filePtr = filesys_open(token);

	if(filePtr != NULL){
		file_close(filePtr);
		sema_up(&fileSystemSema);
		return process_execute(fileName);
	}else{
		sema_up(&fileSystemSema);
		return -1;
	}
}

struct fileStructute* searchList(struct list* filesList, int fd){
	struct list_elem* element;
	element = list_begin(filesList);
	while(element != list_end(filesList)){
		struct fileStructure* newFile = list_entry(element, struct fileStructre, element);
		if(newFile->fd == fd){
			return newFile;
		}
		element = list_next(element);
	}
}

void closeFiles(struct list* filesList){
	struct list_elem* element;
	while(!list_empty(filesList)){
		element = list_pop_front(filesList);
		struct fileStructure* filePtr = list_entry(element, struct fileStructute, element);
		file_close(filePtr->ptr);
		list_remove(element);
		free(filePtr);
	}
}
