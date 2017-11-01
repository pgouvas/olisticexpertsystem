package eu.paasword.drools.risk;


public class Path {
    
    private String vuln;    
    private String from;    
    private String to;    

    public Path(String vuln, String from, String to) {
        this.vuln = vuln;
        this.from = from;
        this.to = to;
    }
  
    public String getVuln() {
        return vuln;
    }

    public void setVuln(String vuln) {
        this.vuln = vuln;
    }

    public String getFrom() {
        return from;
    }

    public void setFrom(String from) {
        this.from = from;
    }

    public String getTo() {
        return to;
    }

    public void setTo(String to) {
        this.to = to;
    }
    
       
}