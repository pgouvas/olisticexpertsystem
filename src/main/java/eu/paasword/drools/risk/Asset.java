package eu.paasword.drools.risk;

import java.util.ArrayList;
import java.util.List;

public class Asset {

    private String id;
    private int type;                       //0-hardware  1-OS   2-App
    private boolean isentrypoint;
    private boolean istarget;
    private List<Vulnerability> vulnerabilities;

    public Asset(String id, int type) {
        this.id = id;
        this.type = type;
        this.isentrypoint = false;
        this.istarget = false;
        vulnerabilities = new ArrayList<>();
    }

    public Asset(String id, int type, boolean isentrypoint, boolean istarget) {
        this.id = id;
        this.type = type;
        this.isentrypoint = isentrypoint;
        this.istarget = istarget;
        vulnerabilities = new ArrayList<>();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public boolean isIsentrypoint() {
        return isentrypoint;
    }

    public void setIsentrypoint(boolean isentrypoint) {
        this.isentrypoint = isentrypoint;
    }

    public boolean isIstarget() {
        return istarget;
    }

    public void setIstarget(boolean istarget) {
        this.istarget = istarget;
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }
    
    public void addVulnerability(Vulnerability vuln){
        this.vulnerabilities.add(vuln);
    }
    
}//EoC
