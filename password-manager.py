from tkinter import *
import tkinter as tk
import random
import string
from cryptography.fernet import Fernet
import os

def generar_clave():
    clave = Fernet.generate_key()
    with open("clave.key", "wb") as clave_file:
        clave_file.write(clave)

if not os.path.exists('clave.key'):
    generar_clave()
    print("El archivo 'clave.key' no existe.")

contraseñasNombre = []
contraseñas = []

lower = string.ascii_lowercase
upper = string.ascii_uppercase
num = string.digits
symbols = string.punctuation
chars_complete = lower + upper + num + symbols
chars_no_symbols = lower + upper + num

# Proceso de encriptación
def cargar_clave():
    return open("clave.key", "rb").read()

def encriptar(nom_archivo, clave):
    f = Fernet(clave)
    with open(nom_archivo, "rb") as file:
        archivo_info = file.read()
    encriptado = f.encrypt(archivo_info)
    with open(nom_archivo, "wb") as file:
        file.write(encriptado)

def desencriptar(nom_archivo, clave):
    f = Fernet(clave)
    with open(nom_archivo, "rb") as file:
        encriptado = file.read()
    desencriptado = f.decrypt(encriptado)
    with open(nom_archivo, "wb") as file:
        file.write(desencriptado)

# Cargar la clave de encriptación
clave = cargar_clave()
nom_archivo = "contraseñas.txt"

def vista_contraseña(ventana_verContraseñas):
    if not contraseñasNombre:
        mensaje_label = tk.Label(ventana_verContraseñas, text="No tienes contraseñas guardadas.")
        mensaje_label.pack()
        return
    
    for i in range(len(contraseñasNombre)):
        contra = contraseñas[i]
        contraseñasTemp = contraseñasNombre[i] + ": " + contraseñas[i]
        mensaje_label = tk.Label(ventana_verContraseñas, text=contraseñasTemp)
        mensaje_label.pack()
        
        def copiar_al_portapapeles(contra=contra):
            ventana_verContraseñas.clipboard_clear()
            ventana_verContraseñas.clipboard_append(contra)

        copiar = Button(ventana_verContraseñas, text="Copiar Contraseña", command=copiar_al_portapapeles)
        copiar.pack()
        
        eliminar = Button(ventana_verContraseñas, text="Eliminar Contraseña", command=lambda i=i: eliminar_contraseña(ventana_verContraseñas, i))
        eliminar.pack()

def eliminar_contraseña(ventana_verContraseñas, indice):
    # Elimina la contraseña de las listas en memoria
    del contraseñasNombre[indice]
    del contraseñas[indice]
    
    # Reescribe el archivo de texto sin la contraseña eliminada
    guardar_contraseñas_en_archivo()
    
    # Cierra la ventana de ver contraseñas y vuelve a abrirla para actualizar la vista
    ventana_verContraseñas.destroy()
    abrir_ventana_verContraseñas()

def añadir_contraseña(ventana_añadirContraseñas):
    global contraseña_Nombre_entry, contraseña_entry
    
    contraseña_Nombre_label = tk.Label(ventana_añadirContraseñas, text="Ingresa el correo/usuario:")
    contraseña_Nombre_label.pack()
    contraseña_Nombre_entry = tk.Entry(ventana_añadirContraseñas)
    contraseña_Nombre_entry.pack()

    contraseña_label = tk.Label(ventana_añadirContraseñas, text="Ingresa una contraseña:")
    contraseña_label.pack()
    contraseña_entry = tk.Entry(ventana_añadirContraseñas)
    contraseña_entry.pack()

    # Botón para guardar la contraseña
    boton_guardar = tk.Button(
        ventana_añadirContraseñas,
        text="Guardar Contraseña",
        command=lambda: guardar_Contraseñas(ventana_añadirContraseñas)
    )
    boton_guardar.pack()

def guardar_Contraseñas(ventana_añadirContraseñas):
    nombre = contraseña_Nombre_entry.get()
    contraseña = contraseña_entry.get()
    if nombre and contraseña:
        contraseñasNombre.append(nombre)
        contraseñas.append(contraseña)
        guardar_contraseñas_en_archivo()  # Guarda las contraseñas en el archivo
        ventana_añadirContraseñas.destroy()
    else:
        error_label = tk.Label(ventana_añadirContraseñas, text="Por favor, completa ambos campos.", fg="red")
        error_label.pack()

def guardar_contraseñas_en_archivo():
    with open(nom_archivo, "w") as file:
        for nombre, contraseña in zip(contraseñasNombre, contraseñas):
            file.write(f"{nombre}:{contraseña}\n")
    encriptar(nom_archivo, clave)

def leer_contraseñas_desde_archivo():
    try:
        desencriptar(nom_archivo, clave)
        with open(nom_archivo, "r") as file:
            for line in file:
                nombre, contraseña = line.strip().split(":")
                contraseñasNombre.append(nombre)
                contraseñas.append(contraseña)
        encriptar(nom_archivo, clave)
    except FileNotFoundError:
        # Si el archivo no existe, simplemente continúa
        pass

def datos_generar_contraseña(ventana_generarContraseñas):
    global contraseña_longitud_entry, var, longitud, contraseña
    contraseña_longitud = tk.Label(ventana_generarContraseñas, text="Ingresa la longitud (máximo 20 dígitos):")
    contraseña_longitud.pack()
    contraseña_longitud_entry = tk.Entry(ventana_generarContraseñas)
    contraseña_longitud_entry.pack()

    var = tk.IntVar()
    checkbox = tk.Checkbutton(ventana_generarContraseñas, text="Deseo que mi contraseña tenga caracteres especiales", variable=var)
    checkbox.pack()

    boton_guardar_datos = tk.Button(
        ventana_generarContraseñas,
        text="Generar Contraseña",
        command=lambda: generar_Contraseñas(ventana_generarContraseñas)
    )
    boton_guardar_datos.pack()

def generar_Contraseñas(ventana_generarContraseñas):
    global error_label

    if 'error_label' in globals():
        error_label.destroy()

    try:
        longitud = int(contraseña_longitud_entry.get())
        if longitud <= 0 or longitud > 20:
            raise ValueError("Longitud fuera de rango")
    except ValueError:
        if not contraseña_longitud_entry.get():
            error_label = tk.Label(ventana_generarContraseñas, text="Por favor, ingresa una longitud.", fg="red")
        else:
            error_label = tk.Label(ventana_generarContraseñas, text="Longitud fuera de rango. Ingrese un número entre 1 y 20.", fg="red")
        error_label.pack()
        return

    if var.get() == 1:
        contraseña = "".join(random.sample(chars_complete, longitud))
    else:
        contraseña = "".join(random.sample(chars_no_symbols, longitud))
    contraseña_mostrar = tk.Label(ventana_generarContraseñas, text=contraseña)
    contraseña_mostrar.pack()
    contraseña_mostrar.pack(pady=10)
    def copiar_al_portapapeles():
        ventana_generarContraseñas.clipboard_clear()
        ventana_generarContraseñas.clipboard_append(contraseña)

    copiar = Button(ventana_generarContraseñas, text="Copiar Contraseña",command=copiar_al_portapapeles)
    copiar.pack()

def abrir_ventana_añadirContraseñas():
    # Crear una ventana secundaria.
    ventana_añadirContraseñas = tk.Toplevel()
    ventana_añadirContraseñas.title("Añadir Contraseñas")
    ventana_añadirContraseñas.geometry("300x150")  # Establece el tamaño de la ventana
    añadir_contraseña(ventana_añadirContraseñas)

def abrir_ventana_verContraseñas():
    # Crear una ventana secundaria.
    ventana_verContraseñas = tk.Toplevel()
    ventana_verContraseñas.title("Ver Contraseñas")
    ventana_verContraseñas.geometry("300x100")  # Establece el tamaño de la ventana
    vista_contraseña(ventana_verContraseñas)

def abrir_ventana_generarContraseñas():
    # Crear una ventana secundaria.
    ventana_generarContraseñas = tk.Toplevel()
    ventana_generarContraseñas.title("Generar Contraseña")
    datos_generar_contraseña(ventana_generarContraseñas)

def cerrar_programa():
    ventana.destroy()

# Configuración de la ventana principal
ventana = tk.Tk()
ventana.title("Password Manager")
ventana.geometry("300x190")  # Establece el tamaño de la ventana principal

leer_contraseñas_desde_archivo()  # Lee las contraseñas al inicio

# Botón para abrir la ventana de añadir contraseñas
boton_abrir_AñadirContraseñas = tk.Button(
    ventana,
    text="Añadir Contraseñas",
    command=abrir_ventana_añadirContraseñas
)
boton_abrir_AñadirContraseñas.pack(pady=10)  # Centra el botón verticalmente con un margen

# Botón para ver las contraseñas
boton_abrir_VerContraseñas = tk.Button(
    ventana,
    text="Ver mis contraseñas",
    command=abrir_ventana_verContraseñas
)
boton_abrir_VerContraseñas.pack(pady=10)  # Centra el botón verticalmente con un margen

# Botón para generar las contraseñas
boton_abrir_generarContraseñas = tk.Button(
    ventana,
    text="Generar contraseña",
    command=abrir_ventana_generarContraseñas
)
boton_abrir_generarContraseñas.pack(pady=10)  # Centra el botón verticalmente con un margen

boton_cerrar_programa = tk.Button(
    ventana,
    text="Cerrar",
    command=cerrar_programa
)
boton_cerrar_programa.pack(pady=10)  # Centra el botón verticalmente con un margen

mensaje_label = tk.Label(ventana, text="")
mensaje_label.pack()

ventana.mainloop()
