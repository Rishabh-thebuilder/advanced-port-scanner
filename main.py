import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, filedialog

# PDF
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# Graph
import matplotlib.pyplot as plt

COMMON_PORTS = {21:'FTP',22:'SSH',23:'Telnet',80:'HTTP',443:'HTTPS'}
RISK_LEVELS = {21:'HIGH',23:'HIGH',80:'MEDIUM',22:'LOW',443:'LOW'}

# ---------------- SCANNER ----------------
class Scanner:
    def __init__(self,target,start,end):
        self.target=target
        self.start=start
        self.end=end
        self.results=[]
        self.stop_flag=False

    def resolve(self):
        return socket.gethostbyname(self.target)

    def scan_port(self,ip,port):
        try:
            s=socket.socket()
            s.settimeout(0.5)
            if s.connect_ex((ip,port))==0:
                service=COMMON_PORTS.get(port,'Unknown')
                risk=RISK_LEVELS.get(port,'MEDIUM')
                return(port,service,risk)
        except:
            pass
        return None

    def run(self,callback):
        ip=self.resolve()
        total=self.end-self.start+1
        done=0

        with ThreadPoolExecutor(max_workers=200) as exe:
            futures=[exe.submit(self.scan_port,ip,p) for p in range(self.start,self.end+1)]

            for f in as_completed(futures):
                if self.stop_flag: break
                done+=1
                callback('progress',done,total)
                res=f.result()
                if res:
                    self.results.append(res)
                    callback('open',res)

        callback('done',self.results)

# ---------------- REPORT ----------------
def generate_report(target,start,end,results):
    report=[]

    report.append("="*60)
    report.append("SECURITY SCAN ASSESSMENT REPORT")
    report.append("="*60)

    report.append(f"\nTarget: {target}")
    report.append(f"Scan Range: {start}-{end}")
    report.append("Status: Completed\n")

    report.append("OPEN PORTS:")
    for port,service,risk in results:
        report.append(f"Port {port} ({service}) - {risk} RISK")

    report.append(f"\nTotal Open Ports: {len(results)}\n")

    report.append("SMART SUMMARY:")
    report.append("The system detected active services. High-risk ports indicate vulnerabilities that require immediate attention.\n")

    report.append("RECOMMENDATIONS:")
    report.append("- Disable FTP/Telnet")
    report.append("- Use HTTPS instead of HTTP")
    report.append("- Secure SSH configuration")

    return "\n".join(report)

# ---------------- GRAPH ----------------
def generate_graph(results):
    risk_count={'HIGH':0,'MEDIUM':0,'LOW':0}

    for _,_,risk in results:
        risk_count[risk]+=1

    labels=list(risk_count.keys())
    values=list(risk_count.values())

    plt.figure()
    plt.bar(labels,values)
    plt.title("Risk Distribution")
    plt.xlabel("Risk Level")
    plt.ylabel("Number of Ports")
    plt.savefig("risk_graph.png")
    plt.close()

# ---------------- GUI ----------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("🔥 Ultimate Cyber Port Scanner")
        self.geometry("900x600")
        self.configure(bg="#0f172a")

        self.build_ui()

    def build_ui(self):
        frame=ttk.LabelFrame(self,text=" Scan Settings ")
        frame.pack(fill="x",padx=10,pady=10)

        self.target=ttk.Entry(frame,width=25)
        self.target.insert(0,"scanme.nmap.org")
        self.target.grid(row=0,column=1)

        self.start=ttk.Entry(frame,width=8)
        self.start.insert(0,"1")
        self.start.grid(row=0,column=3)

        self.end=ttk.Entry(frame,width=8)
        self.end.insert(0,"1024")
        self.end.grid(row=0,column=5)

        ttk.Button(frame,text="▶ Start",command=self.start_scan).grid(row=1,column=4)
        ttk.Button(frame,text="⏹ Stop",command=self.stop_scan).grid(row=1,column=5)

        self.status=tk.StringVar(value="Idle")
        ttk.Label(self,textvariable=self.status).pack(anchor="w",padx=10)

        self.progress=ttk.Progressbar(self)
        self.progress.pack(fill="x",padx=10,pady=5)

        self.text=tk.Text(self,bg="#020617",fg="white")
        self.text.pack(fill="both",expand=True,padx=10,pady=10)

        self.text.tag_config("high",foreground="#ef4444")
        self.text.tag_config("medium",foreground="#f59e0b")
        self.text.tag_config("low",foreground="#22c55e")

        btn_frame=tk.Frame(self,bg="#0f172a")
        btn_frame.pack()

        ttk.Button(btn_frame,text="📄 Export TXT",command=self.export_txt).pack(side="left",padx=5)
        ttk.Button(btn_frame,text="📄 Export PDF",command=self.export_pdf).pack(side="left",padx=5)
        ttk.Button(btn_frame,text="📊 Show Graph",command=self.show_graph).pack(side="left",padx=5)

    def start_scan(self):
        self.text.delete("1.0",tk.END)

        self.scanner=Scanner(self.target.get(),int(self.start.get()),int(self.end.get()))
        threading.Thread(target=self.scanner.run,args=(self.update_ui,),daemon=True).start()

    def stop_scan(self):
        self.scanner.stop_flag=True

    def update_ui(self,typ,*data):
        if typ=='progress':
            done,total=data
            self.progress['maximum']=total
            self.progress['value']=done
            self.status.set(f"Scanning... {done}/{total}")

        elif typ=='open':
            port,service,risk=data[0]
            tag = 'high' if risk=='HIGH' else 'medium' if risk=='MEDIUM' else 'low'
            icon = '🔴' if risk=='HIGH' else '🟠' if risk=='MEDIUM' else '🟢'
            self.text.insert(tk.END,f"{icon} {port} {service} {risk} RISK\n",tag)

        elif typ=='done':
            self.status.set("Completed")
            report=generate_report(self.target.get(),int(self.start.get()),int(self.end.get()),self.scanner.results)
            self.text.insert(tk.END,"\n"+report)

    def export_txt(self):
        file=filedialog.asksaveasfilename(defaultextension=".txt")
        report=generate_report(self.target.get(),int(self.start.get()),int(self.end.get()),self.scanner.results)
        open(file,'w').write(report)

    def export_pdf(self):
        file=filedialog.asksaveasfilename(defaultextension=".pdf")
        doc=SimpleDocTemplate(file)
        styles=getSampleStyleSheet()
        report=generate_report(self.target.get(),int(self.start.get()),int(self.end.get()),self.scanner.results)

        story=[]
        for line in report.split("\n"):
            story.append(Paragraph(line,styles['Normal']))
            story.append(Spacer(1,10))

        doc.build(story)

    def show_graph(self):
        generate_graph(self.scanner.results)
        import os
        os.system("start risk_graph.png")

if __name__=='__main__':
    app=App()
    app.mainloop()
