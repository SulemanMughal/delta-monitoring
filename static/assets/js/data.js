let teams_list = [
  {
    id: "192.168.0.0",
    text: "Team A",
    ip: "192.168.0.0",
    members: ["User_A", "User_B", "User_C"],
  },
  {
    id: "192.168.0.0",
    text: "Team B",
    ip: "192.168.0.0",
    members: ["User_D", "User_E", "User_F"],
  },
  {
    id: "192.168.3.0",
    text: "Team C",
    ip: "192.168.3.0",
    members: ["User_G", "User_H", "User_I"],
  },
  {
    id: "192.168.4.0",
    text: "Team D",
    ip: "192.168.4.0",
    members: ["User_G", "User_K", "User_L"],
  }
  // {
  //   id: 5,
  //   text: "Team E",
  //   ip: "192.168.5.0",
  //   members: ["User_M", "User_N", "User_O"],
  // },
  // {
  //   id: 6,
  //   text: "Team F",
  //   ip: "192.168.6.0",
  //   members: ["User_P", "User_Q", "User_R"],
  // },
  // {
  //   id: 7,
  //   text: "Team G",
  //   ip: "192.168.7.0",
  //   members: ["User_S", "User_T", "User_U"],
  // },
  // {
  //   id: 8,
  //   text: "Team H",
  //   ip: "192.168.8.0",
  //   members: ["User_V", "User_W", "User_X"],
  // },
];

let users_data = [
  {
    id :"192.168.1.1",
    text: "User_A",
    Team: "Team A",
    ip: "192.168.1.1",
  },
  {
    id : "192.168.1.2",
    text: "User_B",
    Team: "Team A",
    ip: "192.168.1.2",
  },
  {
    id : "192.168.1.3",
    text: "User_C",
    Team: "Team A",
    ip: "192.168.1.3",
  },
  // {
  //   id : "4",
  //   text: "User_D",
  //   Team: "Team B",
  //   ip: "192.168.2.1",
  // },
  // {
  //   id : "5",
  //   text: "User_E",
  //   Team: "Team B",
  //   ip: "192.168.2.2",
  // },
  // {
  //   id : "6",
  //   text: "User_F",
  //   Team: "Team B",
  //   ip: "192.168.2.3",
  // },
  // {
  //   id : "7",
  //   text: "User_G",
  //   Team: "Team C",
  //   ip: "192.168.3.1",
  // },
  // {
  //   id : "8",
  //   text: "User_H",
  //   Team: "Team C",
  //   ip: "192.168.3.2",
  // },
  // {
  //   id : "9",
  //   text: "User_I",
  //   Team: "Team C",
  //   ip: "192.168.3.3",
  // },
  // {
  //   id : "10",
  //   text: "User_J",
  //   Team: "Team D",
  //   ip: "192.168.4.1",
  // },
  // {
  //   id : "11",
  //   text: "User_K",
  //   Team: "Team D",
  //   ip: "192.168.4.2",
  // },
  // {
  //   id : "12",
  //   text: "User_L",
  //   Team: "Team D",
  //   ip: "192.168.4.3",
  // }
  // ,
  // {
  //   id : "13",
  //   text: "User_M",
  //   Team: "Team E",
  //   ip: "192.168.5.1",
  // },
  
];

let challenges_data = [
  {
    id : "192.168.1.11",
    text: "Team A - Challenge - 1",
    Team: "Team A",
    ip: "192.168.1.11",
    port : "3000"
  },
  {
    id : "192.168.1.12",
    text: "Team A - Challenge - 2",
    Team: "Team A",
    ip: "192.168.1.12",
    port : "3001"
  },
  {
    id : "192.168.1.13",
    text: "Team A - Challenge - 3",
    Team: "Team A",
    ip: "192.168.1.13",
    port : "3003"
  },
  {
    id : "192.168.1.14",
    text: "Team A - Challenge - 4",
    Team: "Team A",
    ip: "192.168.1.14",
    port : "3004"
  },
  {
    id : "192.168.2.11",
    text: "Team B - Challenge - 1",
    Team: "Team B",
    ip: "192.168.2.11",
    port : "3000"
  },
  {
    id : "192.168.2.12",
    text: "Team B - Challenge - 2",
    Team: "Team B",
    ip: "192.168.2.12",
    port : "3001"
  },
];



function generateTeams(numTeams) {
  let teamsList = [];

  // Function to generate unique user names
  function generateUniqueUser() {
      const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      return `User_${characters[Math.floor(Math.random() * characters.length)]}`;
  }

  // Function to generate teams
  for (let i = 1; i <= numTeams; i++) {
      let team = {
          id: i,
          text: `Team ${String.fromCharCode(65 + (i - 1) % 26)}`,
          ip: `10.8.${i % 256}.0`,
          members: [],
      };

      // Generate unique members for each team
      for (let j = 0; j < 3; j++) {
          let uniqueUser;
          do {
              uniqueUser = generateUniqueUser();
          } while (team.members.includes(uniqueUser));
          team.members.push(uniqueUser);
      }

      teamsList.push(team);
  }

  return teamsList;
}


function generateSrcPorts(count, startPort = 80, endPort = 65535) {
  const srcPorts = [];

  for (let i = 0; i < count; i++) {
    const port = Math.floor(Math.random() * (endPort - startPort + 1)) + startPort;
    srcPorts.push({ id: String(port), text: String(port) });
  }

  return srcPorts;
}




function generateDstPorts(count, startPort = 80, endPort = 65535) {
  const dstPorts = [];

  for (let i = 0; i < count; i++) {
    const port = Math.floor(Math.random() * (endPort - startPort + 1)) + startPort;
    dstPorts.push({ id: String(i + 1), text: String(port) });
  }

  dstPorts.push({
    id: "65536",
    text: "51049",
  
  })

  return dstPorts;
}




// function generateIPs(count, startIP = "", endIP = "") {
//   const ips = [];

//   for (let i = 0; i < count; i++) {
//     const ip = Math.floor(Math.random() * (endIP - startIP + 1)) + startIP;
//     ips.push({ id: String(i + 1), text: String(ip) });
//   }

//   return ips;
// }