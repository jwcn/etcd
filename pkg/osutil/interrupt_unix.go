// Copyright 2015 The etcd Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !windows,!plan9

package osutil

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// InterruptHandler is a function that is called on receiving a
// SIGTERM or SIGINT signal.
type InterruptHandler func()

var (
	interruptRegisterMu, interruptExitMu sync.Mutex
	// interruptHandlers holds all registered InterruptHandlers in order
	// they will be executed.
	interruptHandlers = []InterruptHandler{}
)

// RegisterInterruptHandler registers a new InterruptHandler. Handlers registered
// after interrupt handing was initiated will not be executed.
// 注册添加停止 etcd 后的执行函数集合
func RegisterInterruptHandler(h InterruptHandler) {
	interruptRegisterMu.Lock()
	defer interruptRegisterMu.Unlock()
	interruptHandlers = append(interruptHandlers, h)
}

// HandleInterrupts calls the handler functions on receiving a SIGINT or SIGTERM.
// 开个协程, 用于接收和处理 SIGINT 和 SIGTERM 信号, 调用对应函数s
func HandleInterrupts() {
	notifier := make(chan os.Signal, 1)
	signal.Notify(notifier, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		// 收到停止信号
		sig := <-notifier

		// 获取所有注册过的信号量函数
		interruptRegisterMu.Lock()
		ihs := make([]InterruptHandler, len(interruptHandlers))
		copy(ihs, interruptHandlers)
		interruptRegisterMu.Unlock()

		interruptExitMu.Lock()

		plog.Noticef("received %v signal, shutting down...", sig)

		// 执行所有注册过的 etcd 的清理函数
		for _, h := range ihs {
			h()
		}
		// channel:notifier 停止接收信号量
		signal.Stop(notifier)
		pid := syscall.Getpid()
		// exit directly if it is the "init" process, since the kernel will not help to kill pid 1.
		// 如果当前是主进程, 则直接退出
		if pid == 1 {
			os.Exit(0)
		}
		// 调用内核函数, 还不是很明白
		setDflSignal(sig.(syscall.Signal))
		// 干掉进程
		syscall.Kill(pid, sig.(syscall.Signal))
	}()
}

// Exit relays to os.Exit if no interrupt handlers are running, blocks otherwise.
func Exit(code int) {
	interruptExitMu.Lock()
	os.Exit(code)
}
