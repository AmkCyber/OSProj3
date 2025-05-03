#include "io_helper.h"
#include "request.h"

#define MAXBUF (8192)
#define BUFFER_SIZE 30 // needed this line because I tried to compare line 17 (buffer[30]) with an integer; forgot about type difference...

int num_threads = DEFAULT_THREADS;
int buffer_max_size = DEFAULT_BUFFER_SIZE;
int scheduling_algo = DEFAULT_SCHED_ALGO;

//struct int fd filename buffer or buffer size...
typedef struct {
  int fd;
  char filename[MAXBUF];
  int filesize;
} request_t;

//	TODO: add code to create and manage the buffer
// - A bounded buffer to store incoming requests.
request_t buffer[BUFFER_SIZE];
int add_index = 0;
int rm_index = 0;
int queue = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t buffer_full = PTHREAD_COND_INITIALIZER;
pthread_cond_t buffer_empty = PTHREAD_COND_INITIALIZER;


//
// Sends out HTTP response in case of errors
//
void request_error(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg) {
    char buf[MAXBUF], body[MAXBUF];
    
    // Create the body of error message first (have to know its length for header)
    sprintf(body, ""
	    "<!doctype html>\r\n"
	    "<head>\r\n"
	    "  <title>CYB-3053 WebServer Error</title>\r\n"
	    "</head>\r\n"
	    "<body>\r\n"
	    "  <h2>%s: %s</h2>\r\n" 
	    "  <p>%s: %s</p>\r\n"
	    "</body>\r\n"
	    "</html>\r\n", errnum, shortmsg, longmsg, cause);
    
    // Write out the header information for this response
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    write_or_die(fd, buf, strlen(buf));
    
    sprintf(buf, "Content-Type: text/html\r\n");
    write_or_die(fd, buf, strlen(buf));
    
    sprintf(buf, "Content-Length: %lu\r\n\r\n", strlen(body));
    write_or_die(fd, buf, strlen(buf));
    
    // Write out the body last
    write_or_die(fd, body, strlen(body));
    
    // close the socket connection
    close_or_die(fd);
}

//
// Reads and discards everything up to an empty text line
//
void request_read_headers(int fd) {
    char buf[MAXBUF];
    
    readline_or_die(fd, buf, MAXBUF);
    while (strcmp(buf, "\r\n")) {
		readline_or_die(fd, buf, MAXBUF);
    }
    return;
}

//
// Return 1 if static, 0 if dynamic content (executable file)
// Calculates filename (and cgiargs, for dynamic) from uri
//
int request_parse_uri(char *uri, char *filename, char *cgiargs) {
    char *ptr;
    
    if (!strstr(uri, "cgi")) { 
	// static
	strcpy(cgiargs, "");
	sprintf(filename, ".%s", uri);
	if (uri[strlen(uri)-1] == '/') {
	    strcat(filename, "index.html");
	}
	return 1;
    } else { 
	// dynamic
	ptr = index(uri, '?');
	if (ptr) {
	    strcpy(cgiargs, ptr+1);
	    *ptr = '\0';
	} else {
	    strcpy(cgiargs, "");
	}
	sprintf(filename, ".%s", uri);
	return 0;
    }
}

//
// Fills in the filetype given the filename
//
void request_get_filetype(char *filename, char *filetype) {
    if (strstr(filename, ".html")) 
		strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif")) 
		strcpy(filetype, "image/gif");
    else if (strstr(filename, ".jpg")) 
		strcpy(filetype, "image/jpeg");
    else 
		strcpy(filetype, "text/plain");
}

//
// Handles requests for static content
//
void request_serve_static(int fd, char *filename, int filesize) {
    int srcfd;
    char *srcp, filetype[MAXBUF], buf[MAXBUF];
    
    request_get_filetype(filename, filetype);
    srcfd = open_or_die(filename, O_RDONLY, 0);
    
    // Rather than call read() to read the file into memory, 
    // which would require that we allocate a buffer, we memory-map the file
    srcp = mmap_or_die(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
    close_or_die(srcfd);
    
    // put together response
    sprintf(buf, ""
	    "HTTP/1.0 200 OK\r\n"
	    "Server: OSTEP WebServer\r\n"
	    "Content-Length: %d\r\n"
	    "Content-Type: %s\r\n\r\n", 
	    filesize, filetype);
       
    write_or_die(fd, buf, strlen(buf));
    
    //  Writes out to the client socket the memory-mapped file 
    write_or_die(fd, srcp, filesize);
    munmap_or_die(srcp, filesize);
}

//---------------------------Buffer Modification--------------------------------------------
void buffer_add(request_t arg){
  pthread_mutex_lock(&mutex);
  while (queue == BUFFER_SIZE){ //if queue is full then wait
    pthread_cond_wait(&buffer_empty, &mutex);
  }
  buffer[add_index] = arg; //storing the current request in a buffer by using an index 
  add_index = (add_index + 1) % BUFFER_SIZE; //prevents going over 30 requests in the buffer
  queue++; //increases the amount of requests in the queue
  pthread_cond_signal(&buffer_full);
  pthread_mutex_unlock(&mutex);
}

int fetch_index_fifo() {
  return rm_index;
}

int fetch_index_sff() {
  int index = rm_index;
  int counter = 0;
  for (int i = 0; counter < queue; i = (i + 1) % BUFFER_SIZE, counter++) {
    if (buffer[i].filesize < buffer[index].filesize){
      index = i;
    }
  }
  return index;
}

int fetch_index_random() {
  int counter = 0;
  int plc_hlder[BUFFER_SIZE];
  for (int i = rm_index; counter < queue; i = (i + 1) % BUFFER_SIZE, counter++) {
    plc_hlder[counter] = i;
  }
  int random = rand() % queue;
  return plc_hlder[random];
}

int fetch_index() {
  switch (scheduling_algo) {
    case 0: return fetch_index_fifo();
    case 1: return fetch_index_sff();
    case 2:  return fetch_index_random();
    default: return fetch_index_fifo();
  }
}

//-------------------------------------------------------------------------------------------

// Fetches the requests from the buffer and handles them (thread logic)
// Child threads
void* thread_request_serve_static(void* arg){
	// TODO: write code to actualy respond to HTTP requests
    while (1){
      pthread_mutex_lock(&mutex);
      while (queue == 0){
        pthread_cond_wait(&buffer_full, &mutex);
      }
      int index = fetch_index();
      request_t curr_request = buffer[index]; //starts at bottom
      if (index != rm_index) {//just in case i did something wrong
        buffer[index] = buffer[rm_index];
      }
      rm_index = (rm_index + 1) % BUFFER_SIZE;
      queue--; // logic above doesnt actually remove the request from the queue, it just decreases the queue so that the program thinks there is space, and increments rm_index so that the next request can be selected 
    
      pthread_cond_signal(&buffer_empty);
      pthread_mutex_unlock(&mutex);
      request_serve_static(curr_request.fd, curr_request.filename, curr_request.filesize);
    }
}

// - Security measure to prevent directory traversal attacks.
int check_path(const char *path) {
  return strstr(path, "..") == NULL;
}

// Initial handling of the request
//
void request_handle(int fd) {
    int is_static;
    struct stat sbuf;
    char buf[MAXBUF], method[MAXBUF], uri[MAXBUF], version[MAXBUF];
    char filename[MAXBUF], cgiargs[MAXBUF];
    
	// get the request type, file path and HTTP version
    readline_or_die(fd, buf, MAXBUF);
    sscanf(buf, "%s %s %s", method, uri, version);
    printf("method:%s uri:%s version:%s\n", method, uri, version);

	// verify if the request type is GET or not
    if (strcasecmp(method, "GET")) {
		request_error(fd, method, "501", "Not Implemented", "server does not implement this method");
		return;
    }
    request_read_headers(fd);
    
	// check requested content type (static/dynamic)
    is_static = request_parse_uri(uri, filename, cgiargs);
    
	// get some data regarding the requested file, also check if requested file is present on server
    if (stat(filename, &sbuf) < 0) {
		request_error(fd, filename, "404", "Not found", "server could not find this file");
		return;
    }
    
	// verify if requested content is static
    if (is_static) {
		if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) {
			request_error(fd, filename, "403", "Forbidden", "server could not read this file");
			return;
		}

    // TODO: add cant escape from current directory (changing url to access something we shouldn't) changing test1 to test2, forces a directory change but it could already be accessed so i dont need to worry about it?
    if (!check_path(filename)) {
      request_error(fd, filename, "403", "Forbidden", "directory traversal attempt detected");
      return;
    } 

    //get file size
    request_t request_in;
    request_in.fd = fd;

    //This line: request_in.filename = filename;
    // Had an issue with type difference, didnt know how to type cast for it, and couldnt forget about it since it risks potential buffer overflow
    //So I asked perplexity and it gave this:

    strncpy(request_in.filename, filename, sizeof(request_in.filename) - 1);
    request_in.filename[sizeof(request_in.filename) - 1] = '\0';

    if (stat(filename, &sbuf) == 0) { //check stat output for errors
      request_in.filesize = sbuf.st_size;
    }
    buffer_add(request_in);

    } else {
		request_error(fd, filename, "501", "Not Implemented", "server does not serve dynamic content request");
    }
}