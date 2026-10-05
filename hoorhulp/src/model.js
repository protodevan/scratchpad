import * as T from 'three';
export function createModel(host){
 let renderer;try{renderer=new T.WebGLRenderer({antialias:true,alpha:true});}catch{host.innerHTML='<p>3D is op dit apparaat niet beschikbaar. U kunt alle stappen hieronder blijven volgen.</p>';return {set(){},rotate(){},dispose(){}};}
 renderer.setPixelRatio(Math.min(devicePixelRatio,2));host.appendChild(renderer.domElement);renderer.domElement.setAttribute('aria-label','Schematisch 3D-model van een hoortoestel');renderer.domElement.setAttribute('role','img');
 const scene=new T.Scene(),camera=new T.PerspectiveCamera(36,1,.1,100);camera.position.set(0,.3,8.8);camera.lookAt(0,0,0);
 scene.add(new T.HemisphereLight(0xffffff,0x96836c,3));const light=new T.DirectionalLight(0xffffff,4);light.position.set(3,6,8);scene.add(light);
 const root=new T.Group();scene.add(root);root.rotation.y=-.28;
 const mat=(c)=>new T.MeshStandardMaterial({color:c,roughness:.4,metalness:.08});
 const beige=mat('#b49e7b'),dark=mat('#544c40'),silver=mat('#cdd5d6'),green=mat('#1a8b70');
 const parts={}; const mesh=(name,geo,m,x,y,z,parent=root)=>{const o=new T.Mesh(geo,m.clone());o.position.set(x,y,z);parent.add(o);parts[name]=o;return o;};
 const shape=new T.Shape();shape.moveTo(-.25,-1.15);shape.bezierCurveTo(.6,-1,.9,.5,.65,1.4);shape.bezierCurveTo(.45,2,-.35,2.25,-.7,1.95);shape.bezierCurveTo(-.95,1.72,-.5,1.55,-.32,1.05);shape.bezierCurveTo(.1,.3,-.55,-.8,-.25,-1.15);
 mesh('body',new T.ExtrudeGeometry(shape,{depth:.55,bevelEnabled:true,bevelSegments:8,steps:1,bevelSize:.15,bevelThickness:.16,curveSegments:32}),beige,.5,-.35,-.3);
 const path=pts=>new T.CatmullRomCurve3(pts.map(a=>new T.Vector3(...a)));const tubeMat=new T.MeshPhysicalMaterial({color:'#c8dcd7',roughness:.15,transparent:true,opacity:.78});
 mesh('tube',new T.TubeGeometry(path([[-.15,1.45,0],[-.7,1.9,0],[-1.5,1.45,0],[-1.85,.5,.1],[-1.9,-.6,.2],[-1.45,-1.1,.25]]),64,.105,12,false),tubeMat,0,0,0);
 const mold=mesh('mold',new T.SphereGeometry(.48,32,24),new T.MeshPhysicalMaterial({color:'#dcbea6',transparent:true,opacity:.86,roughness:.26}),-1.45,-1.25,.25);mold.scale.set(1,1.2,.65);
 const rim=mesh('moldrim',new T.TorusGeometry(.36,.1,12,32,4.9),mold.material,-1.48,-.9,.22);rim.scale.set(.9,1.5,.8);
 mesh('outlet',new T.CylinderGeometry(.13,.13,.35,24),dark,-1.3,-1.2,.55).rotation.x=Math.PI/2;
 const hinge=new T.Group();hinge.position.set(.5,-1.45,0);root.add(hinge);mesh('drawer',new T.TorusGeometry(.34,.085,12,32),beige,0,.25,.23,hinge);
 const battery=mesh('battery',new T.CylinderGeometry(.27,.27,.19,48),silver,0,.25,.23,hinge);battery.rotation.x=Math.PI/2;
 const can=document.createElement('canvas');can.width=can.height=128;const cx=can.getContext('2d');cx.fillStyle='#d5dddd';cx.fillRect(0,0,128,128);cx.fillStyle='#1c3437';cx.font='bold 90px sans-serif';cx.textAlign='center';cx.fillText('+',64,94);const tex=new T.CanvasTexture(can);
 const plus=new T.Mesh(new T.CircleGeometry(.23,32),new T.MeshBasicMaterial({map:tex}));plus.position.set(0,.25,.337);hinge.add(plus);
 mesh('button',new T.BoxGeometry(.24,.65,.13),dark,1.26,.35,.1);mesh('mic',new T.SphereGeometry(.07,16,12),dark,.84,1.38,.43);
 const ear=mesh('ear',new T.TorusGeometry(1.25,.22,16,64,5.5),mat('#d9b8a0'),-.65,-.1,-.9);ear.scale.set(.7,1.45,1);ear.visible=false;
 let mode='normal',angle=-.28;
 const badge=document.createElement('div');badge.style.cssText='position:absolute;left:8px;top:8px;font-size:18px;font-weight:bold;background:#ffffffdd;padding:8px 12px;border-radius:10px';host.appendChild(badge);
 function draw(){const w=host.clientWidth,h=host.clientHeight;renderer.setSize(w,h,false);camera.aspect=w/h;camera.updateProjectionMatrix();renderer.render(scene,camera);}
 function set(m){mode=m;badge.textContent=({body:'Behuizing',tube:'Haak en slangetje',mold:'Hard oorstukje',mic:'Microfoonopening',button:'Dubbele knop',open:'Batterijlade open',closed:'Batterijlade dicht',batteryout:'Batterij uit de lade',batteryin:'Batterij in de lade',timer:'Wachten op de batterij',sides:'BLAUW = LINKS · ROOD = RECHTS',detach:'Slangetje en oorstukje los',wash:'Alleen het losse deel wassen',volume:'Oefenen met volume',mute:'Dempen',wear:'Toestel achter het oor',insert:'Oorstukje plaatsen',remove:'Toestel van het oor tillen'})[m]||'Uw oefentoestel';hinge.rotation.z=['open','battery','batteryout','timer','batteryin'].includes(m)?-1.8:0; battery.position.set(0,.25,.23);plus.position.set(0,.25,.337);const out=['batteryout','timer'].includes(m);if(out){battery.position.set(-.45,-.75,.8);plus.position.set(-.45,-.75,.907);}parts.drawer.visible=!out;ear.visible=['wear','insert','remove'].includes(m);parts.tube.position.x=['detach','wash'].includes(m)?-.5:0;parts.mold.position.x=-1.45+(['detach','wash'].includes(m)?-.5:0);parts.moldrim.position.x=-1.48+(['detach','wash'].includes(m)?-.5:0);parts.outlet.position.x=-1.3+(['detach','wash'].includes(m)?-.5:0);for(const [k,o]of Object.entries(parts)){if(o.material?.emissive)o.material.emissive.set('#000000');}const key={closed:'drawer',open:'drawer',batteryin:'battery',batteryout:'battery',timer:'battery',volume:'button',mute:'button',insert:'mold',wear:'body',wash:'mold'}[m]||m;if(parts[key]?.material.emissive)parts[key].material.emissive.set('#284d24');root.rotation.y=angle;draw();}
 const observer=new ResizeObserver(draw);observer.observe(host);set('normal');
 return {set,rotate(delta){angle+=delta;set(mode)},dispose(){observer.disconnect();scene.traverse(o=>{o.geometry?.dispose();if(o.material){o.material.map?.dispose();o.material.dispose();}});renderer.dispose();host.replaceChildren();}};
}
