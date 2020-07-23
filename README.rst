=======================
resource-monitor Readme
=======================

This tool is intended for use within a Taskcluster task payload,
and provides resource usage for the specified process tree, written out
as a json file.


--------
Building
--------

For the current host platform:

.. code-block:: bash

    go build .


For cross-compilation, specify `GOOS` and `GOARCH` environment variables. 

.. code-block:: bash

    GOOS=windows GOARCH=amd64 go build . # results in resource-monitor.exe
    GOOS=windows GOARCH=386 go build .   # results in 32bit resource-monitor.exe
    GOOS=darwin GOARCH=amd64 go build .  # MacOS binary
    GOOS=linux GOARCH=amd64 go build .   # Linux 64bit binary


-------
Running
-------

.. code-block:: bash

    resource-monitor -output /path/to/output.json -process process-id

Terminating the program with ctrl-c will cause it to summarise the data and write to the output file.

On Linux or MacOS:

.. code-block:: python

    process = subprocess.Popen(['resource-monitor', '-output', 'outputfile.json', '-process', os.getpid()])
    ...    
    process.terminate()  # Send SIGTERM
    process.wait()


On Windows, signals operate differently and so we must send a `CTRL_BREAK_EVENT` while also ensuring the resource monitor is in its own process group

.. code-block:: python

    process = subprocess.Popen(['resource-monitor', '-output', 'outputfile.json', '-process', os.getpid()], creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    ...
    os.kill(process.pid, signal.CTRL_BREAK_EVENT)


