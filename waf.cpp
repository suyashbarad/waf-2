#include<iostream>
#include<string>
#include<fstream>
#include<sstream>
#include<map>

// #define MAX_ATTACKS 3
using namespace std;
  
bool isSQL_XSS_Inject(string req){
    ifstream sql_XSS_File("rules.txt");

    if(!sql_XSS_File.is_open()){
        cout<<"Unable to open rules.txt"<<endl;
        return false;
    }
    string rule;
    while(getline(sql_XSS_File, rule)){
        if(req.find(rule) != string::npos){
            return true;
        }
    }
    return false;  
}
int main(){
    ifstream file("request.txt");
    ofstream log("log.txt", ios::app);   //continuous appends all the readed data inot log file
    string line;                         //without erasing the old data
    if(!file.is_open()){
        cout<<"Unable to open request.txt"<<endl;
        return 1;
    } 
    ofstream backend("backend.txt", ios::app);    //for passed files
    backend<<"--------------Backend Files----------------\n\n-------------------------------------------\n";
    if(!backend.is_open()){
        cout<<"Unable to open backend.txt"<<endl;
        return 1;
    }
    ifstream config("config.txt");          //to get max attacks count configuration
    string config_line;
    if(!config.is_open()){
        cout<<"Unable to open config.txt"<<endl;
        return 1;
    }
    getline(config, config_line);
    stringstream conf(config_line);
    string key, value;
    getline(conf, key, '=');
    getline(conf, value);

    int MAX_ATTACKS = stoi(value);
    map <string, int> ipcount;  
    while(getline(file, line)){
        stringstream ss(line);           //stringstream extracts first string of line and names it as "line";
        
        string ip;
        ss >> ip;

        string request;
        
        getline(ss, request);
        if(isSQL_XSS_Inject(request)){

            ipcount[ip]++;

            cout<<"IP: "<<ip<<endl;
            log<<"IP: "<<ip<<endl;
            cout<<"Request == ( "<< request <<" ) \n";
            log<<"Request == ( "<< request << " ) " << endl;
            cout<<"Status: Blocked"<<endl;
            log<<"Status: Blocked"<<endl;
            cout<<"Times attacked: "<<ipcount[ip]<<endl;
            log<<"Times attacked: "<<ipcount[ip]<<endl;
            cout<<"-------------------------------------------\n";
            log<<"-------------------------------------------\n";
            if(ipcount[ip] >= MAX_ATTACKS){
                cout<<"Blocked: "<<ip<<" attacked more than "<< MAX_ATTACKS <<" times ("<<ipcount[ip]<<" times)"<<endl;
                log<<"Blocked: "<<ip<<" attacked more than "<< MAX_ATTACKS <<" times ("<<ipcount[ip]<<" times)"<<endl;
                cout<<"-------------------------------------------\n";
                log<<"-------------------------------------------\n";
                continue;
            }
        }
        else{
            cout<<"IP: "<<ip<<endl;
            log<<"IP: "<<ip<<endl;
            cout<<"Request == ( "<< request <<" ) \n";
            log<<"Request == ( "<< request << " ) " << endl;
            cout<<"Status: Safe"<<endl;
            log<<"Status: Safe"<<endl;
            backend<<"IP: "<<ip<<endl;
            backend<<"Request recieved == ( "<< request << " ) " << endl;
            backend<<"-------------------------------------------\n";
            cout<<"-------------------------------------------\n";
            log<<"-------------------------------------------\n";
        }
    }
        
    cout<<"\n--------------Attack Summary----------------\n";
    log<<"\n--------------Attack Summary----------------\n";

    for(auto x: ipcount){
        if(ipcount[x.first] < MAX_ATTACKS){
            cout<<x.first<<" == "<<x.second<<" times"<<endl;
            log<<x.first<<" == "<<x.second<<" times"<<endl;
        }
        else{
            cout<<x.first<<" == "<<x.second<<" times -- WARNING exceeded "<< MAX_ATTACKS <<" attacks"<<endl;
            log<<x.first<<" == "<<x.second<<" times -- WARNING"<<endl;
        }
    }
    return 0;
}