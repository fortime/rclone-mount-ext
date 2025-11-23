# Introduction

A tool to improve `rclone mount`. It will read a sleep signal to stop `rclone` to prevent a io hanging application from stopping the sleep. And it will try to call `rclone mount` after the system is resumed.
