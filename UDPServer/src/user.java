public class user {

	 private String user;
	    public String id, name, year, month, value, type;

	    public user(String id, String name, String year, String month, String value, String type) {
	        this.user = "user";
	        this.id = id;
	        this.name = name;
	        this.year = year;
	        this.month = month;
	        this.value = value;;
	        this.type = type;
	    }
	    user(String string) {
	        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	    }
	    public String getUser() {
	        return user;
	    }
	    public String getId() {
	        return id;
	    }
	    public String getName() {
	        return name;
	    }
	    public String getYear() {
	        return year;
	    }
	    public String getMonth() {
	        return month;
	    }
	    public String getValue() {
	        return value;
	    }
	    public String getType() {
	        return type;
	    }
	    public void setUser(String user) {
	        this.user = user;
	    }
	    public void setId(String id) {
	        this.id = id;
	    }
	    public void setName(String name) {
	        this.name = name;
	    }	    
	    public void setYear(String year) {
	        this.year = year;
	    }
	    public void setMonth(String month) {
	        this.month = month;
	    }
	    public void setValue(String value) {
	        this.value = value;
	    }
	    public void setType(String type) {
	        this.type = type;
	    }
}