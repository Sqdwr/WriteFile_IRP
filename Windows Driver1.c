#include <ntifs.h>
#include <ntddk.h>

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("Unload Success!\n"));
}

NTSTATUS IoCompletionRoutine(PDEVICE_OBJECT DeviceObject,PIRP Irp,PVOID Context)
{
	*Irp->UserIosb = Irp->IoStatus;
	if (Irp->UserEvent)
		KeSetEvent(Irp->UserEvent, IO_NO_INCREMENT, 0);

	if (Irp->MdlAddress)
	{
		IoFreeMdl(Irp->MdlAddress);
		Irp->MdlAddress = NULL;
	}
	IoFreeIrp(Irp);
	return STATUS_MORE_PROCESSING_REQUIRED;

}

NTSTATUS IrpWriteFile(PFILE_OBJECT FileObject,PIO_STATUS_BLOCK  IoStatusBlock,PVOID  Buffer,ULONG Length,PLARGE_INTEGER ByteOffset)
{

	NTSTATUS Status;
	PIO_STACK_LOCATION IrpSp;
	PIRP Irp;
	KEVENT kEvent;

	if (FileObject->Vpb == 0 || FileObject->Vpb->DeviceObject == NULL)
		return STATUS_UNSUCCESSFUL;
	if (ByteOffset == NULL)
	{
		if (!(FileObject->Flags & FO_SYNCHRONOUS_IO))
			return STATUS_INVALID_PARAMETER;

		ByteOffset = &FileObject->CurrentByteOffset;
	}

	Irp = IoAllocateIrp(FileObject->Vpb->DeviceObject->StackSize, FALSE);
	if (Irp == NULL) 
		return STATUS_INSUFFICIENT_RESOURCES;

	if (FileObject->DeviceObject->Flags & DO_BUFFERED_IO)
		Irp->AssociatedIrp.SystemBuffer = Buffer;
	else
	{
		Irp->MdlAddress = IoAllocateMdl(Buffer, Length, 0, 0, 0);
		if (Irp->MdlAddress == NULL)
		{
			IoFreeIrp(Irp);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		MmBuildMdlForNonPagedPool(Irp->MdlAddress);
	}

	KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);
	Irp->UserEvent = &kEvent;
	Irp->UserIosb = IoStatusBlock;
	Irp->RequestorMode = KernelMode;
	Irp->Flags = IRP_WRITE_OPERATION;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->Tail.Overlay.OriginalFileObject = FileObject;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_WRITE;
	IrpSp->MinorFunction = IRP_MN_NORMAL;
	IrpSp->DeviceObject = FileObject->Vpb->DeviceObject;
	IrpSp->FileObject = FileObject;
	IrpSp->Parameters.Write.Length = Length;
	IrpSp->Parameters.Write.ByteOffset = *ByteOffset;

	IoSetCompletionRoutine(Irp, IoCompletionRoutine, NULL, TRUE, TRUE, TRUE);

	Status = IoCallDriver(FileObject->Vpb->DeviceObject, Irp);

	if (Status == STATUS_PENDING)
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, TRUE, NULL);

	return IoStatusBlock->Status;

}

NTSTATUS WriteFile(WCHAR *w_FileName, PVOID Buffer,ULONG BufferLength,ULONG FileOffset)
{
	UNICODE_STRING u_FileName = { 0 };
	PFILE_OBJECT FileObject = NULL;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	LARGE_INTEGER ByteOffset = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE FileHandle = NULL;
	IO_STATUS_BLOCK IoStatus = { 0 };
	OBJECT_ATTRIBUTES ObjAttr = { 0 };

	RtlInitUnicodeString(&u_FileName, w_FileName);

	InitializeObjectAttributes(&ObjAttr, &u_FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, 0);
	Status = IoCreateFile(
		&FileHandle,
		FILE_WRITE_DATA | SYNCHRONIZE,
		&ObjAttr,
		&IoStatus,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		0,
		NULL,
		IO_CHECK_CREATE_PARAMETERS | IO_NO_PARAMETER_CHECKING
		);

	if (!NT_SUCCESS(Status))
		return Status;

	Status = ObReferenceObjectByHandle(FileHandle, FILE_WRITE_ACCESS, *IoFileObjectType, KernelMode, &FileObject, NULL);
	if (!NT_SUCCESS(Status))
		return Status;

	//写入文件的偏移位置
	ByteOffset.LowPart = FileOffset;

	Status = IrpWriteFile(FileObject, &IoStatusBlock, Buffer, BufferLength, &ByteOffset);

	ObDereferenceObject(FileObject);

	if (!NT_SUCCESS(Status))
		KdPrint(("调用IrpWriteFile失败！错误码是：%x\n", Status));
		
	return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	WCHAR WriteBuffer[] = L"123456789";
	NTSTATUS Status;

	KdPrint(("Entry Driver!\n"));
	Status = WriteFile(L"\\??\\C:\\a.txt", WriteBuffer, sizeof(WriteBuffer),0);
	KdPrint(("%x\n", Status));

	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}