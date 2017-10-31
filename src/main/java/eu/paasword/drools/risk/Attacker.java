package eu.paasword.drools.risk;


public class Attacker {

    private String id;
    private int skill;      //0-Low  1-Medium  2-High    

    public Attacker(String id, int skill) {
        this.id = id;
        this.skill = skill;
    }    
    
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public int getSkill() {
        return skill;
    }

    public void setSkill(int skill) {
        this.skill = skill;
    }
    
}
