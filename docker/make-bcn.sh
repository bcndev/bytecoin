#!/bin/bash

#If you enabled Selinux, you need this command:
#sudo chcon -Rt svirt_sandbox_file_t save

echo 'Detect docker host system'
if df -h | grep atomic ; then
echo 'Atomic docker host'
export PATH=/usr/local/bin:$PATH
else
echo 'Another docker host'
fi

function build
{
if [ ! -d "save" ]; then
  mkdir save
fi

docker-compose build
}

function up
{
docker-compose up
}

function leave
{
echo 'Error compile'
/bin/false
}

function info1
{
echo 'All compiled files at folder save'
ls -la save
}
echo 'Compile bytecoin devel (gui and daemon) with Docker'
build && up && info1 || leave
