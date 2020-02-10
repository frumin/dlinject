//
//  Helpers.swift
//  dlinject
//
//  Created by Tom Zaworowski on 1/20/20.
//  Copyright © 2020 Acidbits. All rights reserved.
//

import Foundation
import Darwin

struct BSD {
    
    struct Process {
        let name: String
        let owner: String
        let pid: pid_t
        
        init?(info: kinfo_proc) {
            guard let uid = getpwuid(info.kp_eproc.e_ucred.cr_uid) else { return nil }
            var process = info.kp_proc
            let capacity = MemoryLayout.size(ofValue: process.p_comm)
            
            pid = info.kp_proc.p_pid
            name = withUnsafePointer(to: &process.p_comm) {
                $0.withMemoryRebound(to: UInt8.self, capacity: capacity) {
                    String(cString: $0)
                }
            }
            owner = String(cString: uid.pointee.pw_name)
        }
    }
    
    static var processes: [Process]? {
        var done = false
        var result: [kinfo_proc]?
        var err: Int32
        
        repeat {
            var name = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0];
            
            let namePointer = name.withUnsafeMutableBufferPointer({ UnsafeMutablePointer<Int32>($0.baseAddress) })
            
            var length: Int = 0
            
            err = sysctl(namePointer, u_int(name.count), nil, &length, nil, 0)
            if err == -1 {
                err = errno
            }
            
            if err == 0 {
                let count = length / MemoryLayout.stride(ofValue: kinfo_proc())
                result = [kinfo_proc](repeating: kinfo_proc(), count: count)
                err = result!.withUnsafeMutableBufferPointer({ ( p: inout UnsafeMutableBufferPointer<kinfo_proc>) -> Int32 in
                    return sysctl(namePointer, u_int(name.count), p.baseAddress, &length, nil, 0)
                })
                switch err {
                case 0:
                    done = true
                case -1:
                    err = errno
                case ENOMEM:
                    err = 0
                default:
                    fatalError()
                }
            }
        } while err == 0 && !done
        
        return result?.compactMap(Process.init)
    }
}
