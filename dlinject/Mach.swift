//
//  Mach.swift
//  dlinject
//
//  Created by Tom Zaworowski on 1/20/20.
//  Copyright © 2020 Acidbits. All rights reserved.
//

import Foundation

struct Mach {
    static func getTask(for pid: pid_t) -> UnsafeMutablePointer<mach_port_t>? {
        print("attempting to get port for \(pid)")
        let selfTask = task_self_trap()
        let task: UnsafeMutablePointer<mach_port_t> = .allocate(capacity: 1)
        let kerr = task_for_pid(selfTask, pid, task)
        guard kerr == KERN_SUCCESS else {
            if let errorDesc = String(cString: mach_error_string(kerr), encoding: .utf8) {
                print(errorDesc)
            } else{
                print("failed to get task_for_pid: \(kerr)")
            }
            return nil
        }
        return task
    }
}
