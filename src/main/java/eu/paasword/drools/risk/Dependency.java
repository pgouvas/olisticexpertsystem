package eu.paasword.drools.risk;

public class Dependency {
    
    private String from;    
    private String to;
    private int type;    //0-IsConnectedTo  1-InstalledOn

    public Dependency(String from, String to, int type) {
        this.from = from;
        this.to = to;
        this.type = type;
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

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }        
    
}
