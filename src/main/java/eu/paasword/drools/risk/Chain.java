package eu.paasword.drools.risk;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;


public class Chain implements Serializable, Cloneable{

    private static final Logger logger = Logger.getLogger(Chain.class.getName());
    
    private String id;    
    private List<Path> paths;
    private List<String> nodes;
    private Path entrypoint;
    private Path tail;

    public Chain() {
        this.id = UUID.randomUUID().toString();        
        paths = new ArrayList<>();
        nodes = new ArrayList<>();        
    }    
    
    public Chain(Path entrypoint) {
        this.id = UUID.randomUUID().toString();
        paths = new ArrayList<>();
        nodes = new ArrayList<>();
        this.entrypoint = entrypoint;        
        addPath(entrypoint);
        nodes.add(entrypoint.getFrom());
        nodes.add(entrypoint.getTo());        
        //logger.info("created id: "+id);
    }    

//    @Override
//    public Chain clone() throws CloneNotSupportedException {
//        return (Chain)super.clone(); //To change body of generated methods, choose Tools | Templates.
//    }
    
    public static Chain cloneChain(Chain oldchain,Path newpath) throws CloneNotSupportedException  {
        Chain newchain = new Chain();
        newchain.paths = new ArrayList<>(oldchain.getPaths());
        newchain.nodes = new ArrayList<>(oldchain.getNodes());
        newchain.setEntrypoint(oldchain.getEntrypoint());
        newchain.addPath(newpath);
        return newchain; //To change body of generated methods, choose Tools | Templates.
    }
    
    public String print()  {
        StringBuffer strb = new StringBuffer();
        strb.append(id+": ");
        strb.append(entrypoint.getFrom());
        for (Path path : paths){
            strb.append(" -> "+path.getTo()+" ("+path.getVuln()+")  ");
        }
        return strb.toString();
    }
    
    public void addPath(Path newpath){
        if (!paths.contains(newpath)) {
            paths.add(newpath);
            nodes.add(newpath.getTo()); 
            tail=newpath;
        }
    }
    
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
    
    public Path getEntrypoint() {
        return entrypoint;
    }

    public void setEntrypoint(Path entrypoint) {
        this.entrypoint = entrypoint;
    }
       
    public List<Path> getPaths() {
        return paths;
    }

    public void setPaths(List<Path> paths) {
        this.paths = paths;
    }

    public Path getTail() {
        return tail;
    }

    public void setTail(Path tail) {
        this.tail = tail;
    }    

    public List<String> getNodes() {
        return nodes;
    }

    public void setNodes(List<String> nodes) {
        this.nodes = nodes;
    }
        
}
