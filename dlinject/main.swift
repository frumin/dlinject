//
//  main.swift
//  dlinject
//
//  Created by Tom Zaworowski on 1/20/20.
//  Copyright © 2020 Acidbits. All rights reserved.
//

import Foundation

class Watcher {
    static let shared = Watcher()
    
    private var treatedPids = [pid_t]()
    private var timer: Timer?
    private var name: String?
    private var path: String?
    
    func watch(name: String, dylibPath: String) {
        self.name = name
        self.path = dylibPath
        timer = Timer.scheduledTimer(timeInterval: 10,
                                     target: self,
                                     selector: #selector(injectProcess),
                                     userInfo: nil,
                                     repeats: true)
        injectProcess()
    }
    
    @objc func injectProcess() {
        guard let name = name, let path = path else { return }
        print("Getting pids for \(name)")
        guard let matches = BSD.processes?.filter({ (process) -> Bool in
            process.name == name && treatedPids.contains(process.pid) == false
        }) else { return }
        print("found \(matches.count) matches")
        
        matches.map { $0.pid }.forEach { (pid) in
            guard let port = Mach.getTask(for: pid) else { return }
            print("injecting \(pid)")
            let kerr = Injector.injectPort(port.pointee, dylibPath: path)
            switch kerr {
            case KERN_SUCCESS: break
            case KERN_INVALID_TASK: print("\(path) couldn't be read by dlopen()")
            default: print("error injecting \(pid)")
            }
            port.deallocate()
            treatedPids.append(pid)
        }
    }
}

var timer: Timer?

func main() {
    let args = CommandLine.arguments

    guard args.count > 2 else { print ("Usage: dlinject <process name> <dylib path>"); return }
    let name = args[1]
    let path = args[2]
    
    Watcher.shared.watch(name: name, dylibPath: path)
    
    RunLoop.current.run()
}

main()
